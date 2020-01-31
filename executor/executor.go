package executor

import (
	"context"
	"io"
	"net"
	"os"

	"github.com/moby/buildkit/util/network"

	"github.com/moby/buildkit/cache"
	"github.com/moby/buildkit/solver/pb"
)

type Meta struct {
	Args           []string
	Env            []string
	User           string
	Cwd            string
	Tty            bool
	ReadonlyRootFS bool
	ExtraHosts     []HostIP
	NetMode        pb.NetMode
	SecurityMode   pb.SecurityMode
}

type Mount struct {
	Src      cache.Mountable
	Selector string
	Dest     string
	Readonly bool
}

type ExecData struct {
	Namespace     network.Namespace
	HostFileClean func()
	MountRelease  func() error
	Bundle        string
	RootFSPath    string
	ConfigJson    *os.File
	SpecCleanup   func()
	CancelRun     context.CancelFunc
	DoneRun       chan struct{}
	ErrorRun      error
	CtrStatus     string
	HasFinished   bool
}

type Executor interface {
	// TODO: add stdout/err
	Exec(ctx context.Context, meta Meta, rootfs cache.Mountable, mounts []Mount, stdin io.ReadCloser, stdout, stderr io.WriteCloser) error

	ExecStart(ctx context.Context, meta Meta, root cache.Mountable, mounts []Mount, stdin io.ReadCloser, stdout, stderr io.WriteCloser) (*ExecData, error)
	ExecEnd(ctx context.Context, execData *ExecData)
}

type HostIP struct {
	Host string
	IP   net.IP
}
