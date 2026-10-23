package storage

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/JUXON-AI/jxpkg/identity"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

type fileConnector struct{ calls int }

func (c *fileConnector) Connect(context.Context) (driver.Conn, error) { return fileConn{c}, nil }
func (*fileConnector) Driver() driver.Driver                          { return fileDriver{} }

type fileDriver struct{}

func (fileDriver) Open(string) (driver.Conn, error) { return nil, errors.New("use isolated connector") }

type fileConn struct{ capture *fileConnector }

func (fileConn) Prepare(string) (driver.Stmt, error) { return nil, errors.New("unexpected prepare") }
func (fileConn) Begin() (driver.Tx, error)           { return nil, errors.New("unexpected transaction") }
func (fileConn) Close() error                        { return nil }
func (c fileConn) QueryContext(_ context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	c.capture.calls++
	if !strings.Contains(query, "organization_id = ? AND user_id = ?") || !strings.Contains(query, "deleted_at` IS NULL") || len(args) != 4 || args[3].Value != int64(1) {
		return nil, errors.New("file lookup lost membership or soft-delete scope")
	}
	return &fileRows{visible: args[0].Value == "org-a" && args[1].Value == "user-a"}, nil
}

type fileRows struct{ visible, done bool }

func (*fileRows) Columns() []string { return []string{"id", "organization_id", "user_id"} }
func (*fileRows) Close() error      { return nil }
func (r *fileRows) Next(values []driver.Value) error {
	if !r.visible || r.done {
		return io.EOF
	}
	r.done = true
	values[0] = int64(7)
	values[1] = "org-a"
	values[2] = "user-a"
	return nil
}

func TestFileLookupsKeepSameUserInDifferentOrganizationsSeparate(t *testing.T) {
	capture := &fileConnector{}
	connection := sql.OpenDB(capture)
	t.Cleanup(func() {
		if err := connection.Close(); err != nil {
			t.Error(err)
		}
	})
	db, err := gorm.Open(mysql.New(mysql.Config{Conn: connection, SkipInitializeWithVersion: true}), &gorm.Config{DisableAutomaticPing: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, lookup := range []func(identity.Member) (*CoreFileInfo, error){
		func(m identity.Member) (*CoreFileInfo, error) { return GetFileByID(db, m, 7) },
		func(m identity.Member) (*CoreFileInfo, error) { return GetFileByHash(db, m, "sha256:synthetic") },
		func(m identity.Member) (*CoreFileInfo, error) {
			return GetFileByPublicURL(db, m, "https://objects.invalid/synthetic")
		},
	} {
		for _, member := range []identity.Member{{OrganizationID: "org-a", UserID: "user-a"}, {OrganizationID: "org-b", UserID: "user-a"}, {OrganizationID: "org-a", UserID: "user-b"}} {
			found, err := lookup(member)
			if member.OrganizationID == "org-a" && member.UserID == "user-a" {
				if err != nil || found.ID != 7 {
					t.Fatal("valid file owner rejected")
				}
				continue
			}
			if !errors.Is(err, gorm.ErrRecordNotFound) || found != nil {
				t.Fatal("file crossed organization or user boundary")
			}
		}
	}
	if capture.calls != 9 {
		t.Fatal("unexpected file query count")
	}
	for _, lookup := range []func() (*CoreFileInfo, error){
		func() (*CoreFileInfo, error) { return GetFileByID(nil, identity.Member{}, 7) },
		func() (*CoreFileInfo, error) { return GetFileByHash(nil, identity.Member{}, "hash") },
		func() (*CoreFileInfo, error) { return GetFileByPublicURL(nil, identity.Member{}, "url") },
	} {
		if _, err := lookup(); !errors.Is(err, identity.ErrInvalidMember) {
			t.Fatal("invalid file owner reached persistence")
		}
	}
}

func TestNewStoragePathsDoNotEmbedRawIdentityAndRejectTraversal(t *testing.T) {
	member := identity.Member{OrganizationID: "org-a", UserID: "../user-a"}
	first, err := GenerateFileStoragePath("attachment", member, ".png")
	if err != nil || len(first) > 255 || strings.Contains(first, "..") || strings.Contains(first, "user-a") {
		t.Fatal("new file key is unsafe or exceeds metadata capacity")
	}
	second, err := GenerateFileStoragePath("attachment", member, ".png")
	if err != nil || first == second {
		t.Fatal("independent objects reused a key")
	}
	other, err := GenerateFileStoragePath("attachment", identity.Member{OrganizationID: "org-b", UserID: member.UserID}, ".png")
	if err != nil || strings.Split(first, "/")[2][:16] == strings.Split(other, "/")[2][:16] {
		t.Fatal("object owner namespace lost organization")
	}
	for _, name := range []string{"../escape", "..", "nested/file", "nested\\file", "name\x00"} {
		if _, err := GenerateFileStoragePathWithName("attachment", member, name); err == nil {
			t.Fatal("invalid object filename accepted")
		}
	}
	for _, purpose := range []string{"", "../escape", "nested/file"} {
		if _, err := GenerateFileStoragePathWithName(purpose, member, "file.png"); err == nil {
			t.Fatal("invalid purpose accepted")
		}
	}
	for _, ext := range []string{"", ".", "png", ".a/b"} {
		if _, err := GenerateFileStoragePath("attachment", member, ext); err == nil {
			t.Fatal("invalid extension accepted")
		}
	}
	if _, err := GenerateFileStoragePath("attachment", identity.Member{}, ".png"); !errors.Is(err, identity.ErrInvalidMember) {
		t.Fatal("object path inferred a missing membership")
	}
}
