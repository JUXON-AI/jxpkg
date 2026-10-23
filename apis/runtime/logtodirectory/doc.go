// Package logtodirectory provides the fixed-purpose client shared by JUXON
// services that read Logto workload-directory snapshots.
//
// The protocol has two accepted consumers: the existing JXX directory
// transport being lifted out of its application package, and JXONE's bounded
// member listing. NewClient only derives the OIDC client-credentials token
// endpoint and the workload-directory snapshot endpoint from an explicit
// HTTPS origin. It does not read environment or database configuration, and
// constructing a client has no network or startup side effect.
//
// ListPage implements the provider's bounded one-page listing contract. The
// caller must deploy a compatible provider and enable allowMemberListing in
// its workload registry. Local provider/database interoperability tests do not
// imply that listing is enabled in a particular deployment.
package logtodirectory
