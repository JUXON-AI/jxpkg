// Package logtodirectory provides the fixed-purpose client shared by JUXON
// services that read Logto workload-directory data.
//
// The protocol has two accepted consumers: the existing JXX directory
// transport being lifted out of its application package, and JXONE's bounded
// member listing. NewClient only derives the OIDC client-credentials token
// endpoint and fixed workload-directory routes from an explicit HTTPS origin.
// It does not read environment or database configuration, and constructing a
// client has no network or startup side effect.
//
// ListPage implements the provider's bounded one-page listing contract. The
// caller must deploy a compatible provider and enable allowMemberListing in
// its workload registry. SearchOrganizations reads the provider's bounded
// organization page. Source-level provider compatibility does not imply either
// capability is enabled in a particular deployment.
package logtodirectory
