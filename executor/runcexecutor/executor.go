package runcexecutor

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/containerd/containerd/mount"
	containerdoci "github.com/containerd/containerd/oci"
	"github.com/containerd/continuity/fs"
	runc "github.com/containerd/go-runc"
	"github.com/docker/docker/pkg/idtools"
	"github.com/moby/buildkit/cache"
	"github.com/moby/buildkit/executor"
	"github.com/moby/buildkit/executor/oci"
	"github.com/moby/buildkit/identity"
	"github.com/moby/buildkit/solver/pb"
	"github.com/moby/buildkit/util/network"
	rootlessspecconv "github.com/moby/buildkit/util/rootless/specconv"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

type Opt struct {
	// root directory
	Root              string
	CommandCandidates []string
	// without root privileges (has nothing to do with Opt.Root directory)
	Rootless bool
	// DefaultCgroupParent is the cgroup-parent name for executor
	DefaultCgroupParent string
	// ProcessMode
	ProcessMode     oci.ProcessMode
	IdentityMapping *idtools.IdentityMapping
	// runc run --no-pivot (unrecommended)
	NoPivot     bool
	DNS         *oci.DNSConfig
	OOMScoreAdj *int
}

var defaultCommandCandidates = []string{"buildkit-runc", "runc"}

type runcExecutor struct {
	runc             *runc.Runc
	root             string
	cmd              string
	cgroupParent     string
	rootless         bool
	networkProviders map[pb.NetMode]network.Provider
	processMode      oci.ProcessMode
	idmap            *idtools.IdentityMapping
	noPivot          bool
	dns              *oci.DNSConfig
	oomScoreAdj      *int
}

func New(opt Opt, networkProviders map[pb.NetMode]network.Provider) (executor.Executor, error) {
	cmds := opt.CommandCandidates
	if cmds == nil {
		cmds = defaultCommandCandidates
	}

	var cmd string
	var found bool
	for _, cmd = range cmds {
		if _, err := exec.LookPath(cmd); err == nil {
			found = true
			break
		}
	}
	if !found {
		return nil, errors.Errorf("failed to find %s binary", cmd)
	}

	root := opt.Root

	if err := os.MkdirAll(root, 0711); err != nil {
		return nil, errors.Wrapf(err, "failed to create %s", root)
	}

	root, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		return nil, err
	}

	// clean up old hosts/resolv.conf file. ignore errors
	os.RemoveAll(filepath.Join(root, "hosts"))
	os.RemoveAll(filepath.Join(root, "resolv.conf"))

	runtime := &runc.Runc{
		Command:      cmd,
		Log:          filepath.Join(root, "runc-log.json"),
		LogFormat:    runc.JSON,
		PdeathSignal: syscall.SIGKILL, // this can still leak the process
		Setpgid:      true,
		// we don't execute runc with --rootless=(true|false) explicitly,
		// so as to support non-runc runtimes
	}

	w := &runcExecutor{
		runc:             runtime,
		root:             root,
		cgroupParent:     opt.DefaultCgroupParent,
		rootless:         opt.Rootless,
		networkProviders: networkProviders,
		processMode:      opt.ProcessMode,
		idmap:            opt.IdentityMapping,
		noPivot:          opt.NoPivot,
		dns:              opt.DNS,
		oomScoreAdj:      opt.OOMScoreAdj,
	}
	return w, nil
}

func (w *runcExecutor) ExecStart(ctx context.Context, meta executor.Meta, root cache.Mountable, mounts []executor.Mount, stdin io.ReadCloser, stdout, stderr io.WriteCloser) (*executor.ExecData, error) {
	execData := &executor.ExecData{}

	provider, ok := w.networkProviders[meta.NetMode]
	if !ok {
		return nil, errors.Errorf("unknown network mode %s", meta.NetMode)
	}
	namespace, err := provider.New()
	if err != nil {
		return execData, err
	}

	execData.Namespace = namespace

	if meta.NetMode == pb.NetMode_HOST {
		logrus.Info("enabling HostNetworking")
	}

	resolvConf, err := oci.GetResolvConf(ctx, w.root, w.idmap, w.dns)
	if err != nil {
		return execData, err
	}

	hostsFile, clean, err := oci.GetHostsFile(ctx, w.root, meta.ExtraHosts, w.idmap)
	if err != nil {
		return execData, err
	}
	if clean != nil {
		execData.HostFileClean = clean
	}

	mountable, err := root.Mount(ctx, false)
	if err != nil {
		return nil, err
	}

	rootMount, release, err := mountable.Mount()
	if err != nil {
		return nil, err
	}
	if release != nil {
		execData.MountRelease = release
	}

	id := identity.NewID()
	bundle := filepath.Join(w.root, id)

	if err := os.Mkdir(bundle, 0711); err != nil {
		return execData, err
	}
	execData.Bundle = bundle

	identity := idtools.Identity{}
	if w.idmap != nil {
		identity = w.idmap.RootPair()
	}

	rootFSPath := filepath.Join(bundle, "rootfs")
	if err := idtools.MkdirAllAndChown(rootFSPath, 0700, identity); err != nil {
		return execData, err
	}
	if err := mount.All(rootMount, rootFSPath); err != nil {
		return execData, err
	}
	execData.RootFSPath = rootFSPath

	uid, gid, sgids, err := oci.GetUser(ctx, rootFSPath, meta.User)
	if err != nil {
		return execData, err
	}

	f, err := os.Create(filepath.Join(bundle, "config.json"))
	if err != nil {
		return execData, err
	}
	execData.ConfigJson = f

	opts := []containerdoci.SpecOpts{oci.WithUIDGID(uid, gid, sgids)}

	if meta.ReadonlyRootFS {
		opts = append(opts, containerdoci.WithRootFSReadonly())
	}

	identity = idtools.Identity{
		UID: int(uid),
		GID: int(gid),
	}
	if w.idmap != nil {
		identity, err = w.idmap.ToHost(identity)
		if err != nil {
			return execData, err
		}
	}

	if w.cgroupParent != "" {
		var cgroupsPath string
		lastSeparator := w.cgroupParent[len(w.cgroupParent)-1:]
		if strings.Contains(w.cgroupParent, ".slice") && lastSeparator == ":" {
			cgroupsPath = w.cgroupParent + id
		} else {
			cgroupsPath = filepath.Join("/", w.cgroupParent, "buildkit", id)
		}
		opts = append(opts, containerdoci.WithCgroup(cgroupsPath))
	}
	spec, cleanup, err := oci.GenerateSpec(ctx, meta, mounts, id, resolvConf, hostsFile, namespace, w.processMode, w.idmap, opts...)
	if err != nil {
		return execData, err
	}
	execData.SpecCleanup = cleanup

	spec.Root.Path = rootFSPath
	if _, ok := root.(cache.ImmutableRef); ok { // TODO: pass in with mount, not ref type
		spec.Root.Readonly = true
	}

	newp, err := fs.RootPath(rootFSPath, meta.Cwd)
	if err != nil {
		return execData, errors.Wrapf(err, "working dir %s points to invalid target", newp)
	}
	if _, err := os.Stat(newp); err != nil {
		if err := idtools.MkdirAllAndChown(newp, 0755, identity); err != nil {
			return execData, errors.Wrapf(err, "failed to create working directory %s", newp)
		}
	}

	spec.Process.OOMScoreAdj = w.oomScoreAdj
	if w.rootless {
		if err := rootlessspecconv.ToRootless(spec); err != nil {
			return execData, err
		}
	}

	if err := json.NewEncoder(f).Encode(spec); err != nil {
		return execData, err
	}

	// runCtx/killCtx is used for extra check in case the kill command blocks
	runCtx, cancelRun := context.WithCancel(context.Background())
	execData.CancelRun = cancelRun

	done := make(chan struct{})
	execData.DoneRun = done
	go func() {
		for {
			select {
			case <-ctx.Done():
				w.killContainer(id, done, cancelRun)
			case <-done:
				if execData.ErrorRun == nil && execData.CtrStatus == "running" {
					w.killContainer(id, done, cancelRun)
				}
				return
			}
		}
	}()

	eg, _ := errgroup.WithContext(context.Background())

	var status int
	eg.Go(func() error {
		logrus.Debugf("> creating %s %v", id, meta.Args)
		status, err = w.runc.Run(runCtx, id, bundle, &runc.CreateOpts{
			IO:      &forwardIO{stdin: stdin, stdout: stdout, stderr: stderr},
			NoPivot: w.noPivot,
		})

		execData.ErrorRun = err
		if !execData.HasFinished {
			close(done)
			execData.HasFinished = true
		}

		if err != nil {
			return err
		}

		return nil
	})

	go func() {
		err = eg.Wait()
	}()

	for {
		if execData.HasFinished {
			break
		}

		c, err := w.runc.State(ctx, id)
		if c == nil {
			continue
		}
		logrus.Debugf(">> container %s, Status: %s", id, c.Status)
		if err != nil {
			logrus.Debugf(">> container %s, Error: %v", id, err)
			break
		}

		execData.CtrStatus = c.Status
		if c.Status == "running" || c.Status == "stopped" {
			break
		}
	}

	if status != 0 || err != nil {
		if err == nil {
			err = errors.Errorf("exit code: %d", status)
		}
		select {
		case <-ctx.Done():
			return execData, errors.Wrapf(ctx.Err(), err.Error())
		default:
			return execData, err
		}
	}

	return execData, nil
}

func (w *runcExecutor) ExecEnd(ctx context.Context, execData *executor.ExecData) {
	if execData.Namespace != nil {
		defer execData.Namespace.Close()
	}

	if execData.HostFileClean != nil {
		defer execData.HostFileClean()
	}

	if execData.MountRelease != nil {
		defer execData.MountRelease()
	}

	if execData.Bundle != "" {
		defer os.RemoveAll(execData.Bundle)
	}

	if execData.RootFSPath != "" {
		defer mount.Unmount(execData.RootFSPath, 0)
	}

	if execData.ConfigJson != nil {
		defer execData.ConfigJson.Close()
	}

	if execData.SpecCleanup != nil {
		defer execData.SpecCleanup()
	}

	if execData.CancelRun != nil {
		defer execData.CancelRun()
	}

	if !execData.HasFinished {
		close(execData.DoneRun)
		execData.HasFinished = true
	}
}

func (w *runcExecutor) killContainer(id string, done chan struct{}, cancelRun func()) {
	killCtx, timeout := context.WithTimeout(context.Background(), 7*time.Second)
	if err := w.runc.Kill(killCtx, id, int(syscall.SIGKILL), nil); err != nil {
		logrus.Errorf("failed to kill runc %s: %+v", id, err)
		select {
		case <-killCtx.Done():
			timeout()
			cancelRun()
			return
		default:
		}
	}
	timeout()
	select {
	case <-time.After(50 * time.Millisecond):
	case <-done:
		return
	}
}

func (w *runcExecutor) Exec(ctx context.Context, meta executor.Meta, root cache.Mountable, mounts []executor.Mount, stdin io.ReadCloser, stdout, stderr io.WriteCloser) error {
	execData, err := w.ExecStart(ctx, meta, root, mounts, stdin, stdout, stderr)

	w.ExecEnd(ctx, execData)
	if err != nil {
		return err
	}

	return nil
}

type forwardIO struct {
	stdin          io.ReadCloser
	stdout, stderr io.WriteCloser
}

func (s *forwardIO) Close() error {
	return nil
}

func (s *forwardIO) Set(cmd *exec.Cmd) {
	cmd.Stdin = s.stdin
	cmd.Stdout = s.stdout
	cmd.Stderr = s.stderr
}

func (s *forwardIO) Stdin() io.WriteCloser {
	return nil
}

func (s *forwardIO) Stdout() io.ReadCloser {
	return nil
}

func (s *forwardIO) Stderr() io.ReadCloser {
	return nil
}
