// Package upstreamidentity defines shared, non-secret GORM schema contracts for
// upstream tenant admission, external identity bindings, and lifecycle events.
//
// It deliberately provides no migration registration or persistence operations.
package upstreamidentity

import "time"

const (
	// TableNameUpstreamFederation stores admitted provider tenants.
	TableNameUpstreamFederation = "account_upstream_federation"
	// TableNameExternalIdentity stores exact external-to-local identity mappings.
	TableNameExternalIdentity = "account_external_identity"
	// TableNameUpstreamEvent stores durable lifecycle event dedupe and delivery state.
	TableNameUpstreamEvent = "account_upstream_event"
)

// UpstreamFederation admits one provider tenant to one Account company.
type UpstreamFederation struct {
	ID             uint      `gorm:"column:id;type:bigint unsigned;primaryKey;autoIncrement;comment:上游租户联合主键" json:"id"`
	ConnectionID   string    `gorm:"column:connection_id;type:varbinary(64);not null;uniqueIndex:uk_upstream_federation_tenant,priority:1;index:idx_upstream_federation_status,priority:1;comment:上游连接唯一标识" json:"connection_id"`
	TenantKey      string    `gorm:"column:tenant_key;type:varbinary(255);not null;uniqueIndex:uk_upstream_federation_tenant,priority:2;comment:上游租户唯一标识" json:"tenant_key"`
	CompanyID      uint      `gorm:"column:company_id;type:bigint unsigned;not null;comment:本地公司标识" json:"company_id"`
	Status         string    `gorm:"column:status;type:varchar(32);not null;index:idx_upstream_federation_status,priority:2;comment:上游租户联合状态" json:"status"`
	Generation     uint64    `gorm:"column:generation;type:bigint unsigned;not null;default:1;comment:上游租户联合状态代次" json:"generation"`
	LastEventOrder int64     `gorm:"column:last_event_order;type:bigint;not null;default:0;comment:最近已应用事件顺序" json:"last_event_order"`
	Reconcile      bool      `gorm:"column:reconcile;type:boolean;not null;default:false;comment:是否需要权威复核" json:"reconcile"`
	CreatedAt      time.Time `gorm:"column:created_at;type:datetime(3);not null;comment:创建时间" json:"created_at"`
	UpdatedAt      time.Time `gorm:"column:updated_at;type:datetime(3);not null;comment:更新时间" json:"updated_at"`
}

// TableName returns the federation table name.
func (UpstreamFederation) TableName() string { return TableNameUpstreamFederation }

// ExternalIdentity is the authoritative upstream principal mapping.
// Email, mobile, name, and legacy provider profile fields are intentionally absent.
type ExternalIdentity struct {
	ID             uint      `gorm:"column:id;type:bigint unsigned;primaryKey;autoIncrement;comment:外部身份主键" json:"id"`
	ProviderRegion string    `gorm:"column:provider_region;type:varbinary(32);not null;uniqueIndex:uk_external_identity_principal,priority:1;comment:上游提供方区域" json:"provider_region"`
	ConnectionID   string    `gorm:"column:connection_id;type:varbinary(64);not null;uniqueIndex:uk_external_identity_principal,priority:2;index:idx_external_identity_user_status,priority:1;comment:上游连接唯一标识" json:"connection_id"`
	TenantKey      string    `gorm:"column:tenant_key;type:varbinary(255);not null;uniqueIndex:uk_external_identity_principal,priority:3;comment:上游租户唯一标识" json:"tenant_key"`
	OpenID         string    `gorm:"column:open_id;type:varbinary(255);not null;uniqueIndex:uk_external_identity_principal,priority:4;comment:上游开放身份标识" json:"open_id"`
	UnionID        string    `gorm:"column:union_id;type:varbinary(255);comment:上游联合身份辅助标识" json:"union_id,omitempty"`
	UpstreamUserID string    `gorm:"column:upstream_user_id;type:varbinary(255);comment:上游可变用户辅助标识" json:"upstream_user_id,omitempty"`
	UserID         uint      `gorm:"column:user_id;type:bigint unsigned;not null;index:idx_external_identity_user_status,priority:2;comment:本地用户标识" json:"user_id"`
	Status         string    `gorm:"column:status;type:varchar(32);not null;index:idx_external_identity_user_status,priority:3;comment:外部身份状态" json:"status"`
	Generation     uint64    `gorm:"column:generation;type:bigint unsigned;not null;default:1;comment:外部身份状态代次" json:"generation"`
	LastEventOrder int64     `gorm:"column:last_event_order;type:bigint;not null;default:0;comment:最近已应用事件顺序" json:"last_event_order"`
	Reconcile      bool      `gorm:"column:reconcile;type:boolean;not null;default:false;comment:是否需要权威复核" json:"reconcile"`
	CreatedAt      time.Time `gorm:"column:created_at;type:datetime(3);not null;comment:绑定创建时间" json:"created_at"`
	UpdatedAt      time.Time `gorm:"column:updated_at;type:datetime(3);not null;comment:绑定更新时间" json:"updated_at"`
}

// TableName returns the external identity table name.
func (ExternalIdentity) TableName() string { return TableNameExternalIdentity }

// UpstreamEvent is an immutable dedupe and revocation-delivery boundary.
// Raw payloads, credentials, authorization codes, and tokens are never persisted.
type UpstreamEvent struct {
	ID               uint       `gorm:"column:id;type:bigint unsigned;primaryKey;autoIncrement;comment:上游事件主键" json:"id"`
	ConnectionID     string     `gorm:"column:connection_id;type:varbinary(64);not null;uniqueIndex:uk_upstream_event,priority:1;comment:上游连接唯一标识" json:"connection_id"`
	EventID          string     `gorm:"column:event_id;type:varbinary(255);not null;uniqueIndex:uk_upstream_event,priority:2;comment:上游事件唯一标识" json:"event_id"`
	EventType        string     `gorm:"column:event_type;type:varchar(128);not null;comment:上游事件类型" json:"event_type"`
	ProviderRegion   string     `gorm:"column:provider_region;type:varbinary(32);not null;comment:上游提供方区域" json:"provider_region"`
	OpenID           string     `gorm:"column:open_id;type:varbinary(255);comment:上游开放身份标识" json:"open_id,omitempty"`
	LifecycleStatus  string     `gorm:"column:lifecycle_status;type:varchar(32);comment:规范化生命周期状态" json:"lifecycle_status,omitempty"`
	TenantKey        string     `gorm:"column:tenant_key;type:varbinary(255);not null;comment:上游租户唯一标识" json:"tenant_key"`
	PayloadHash      string     `gorm:"column:payload_hash;type:char(64);not null;comment:事件明文载荷摘要" json:"payload_hash"`
	EventOrder       int64      `gorm:"column:event_order;type:bigint;not null;comment:上游事件顺序" json:"event_order"`
	Disposition      string     `gorm:"column:disposition;type:varchar(32);not null;comment:事件处理决策" json:"disposition"`
	ProcessingStatus string     `gorm:"column:processing_status;type:varchar(32);not null;index:idx_upstream_event_processing;comment:事件处理状态" json:"processing_status"`
	AffectedUserIDs  []uint     `gorm:"column:affected_user_ids;type:json;serializer:json;not null;comment:待撤销本地用户标识集合" json:"affected_user_ids"`
	CreatedAt        time.Time  `gorm:"column:created_at;type:datetime(3);not null;comment:事件首次接收时间" json:"created_at"`
	ClaimUntil       *time.Time `gorm:"column:claim_until;type:datetime(3);index:idx_upstream_event_processing;comment:权威复核租约截止时间" json:"claim_until,omitempty"`
	CompletedAt      *time.Time `gorm:"column:completed_at;type:datetime(3);comment:事件处理完成时间" json:"completed_at,omitempty"`
}

// TableName returns the upstream event table name.
func (UpstreamEvent) TableName() string { return TableNameUpstreamEvent }
