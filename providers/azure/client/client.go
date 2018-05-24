package azure

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/Azure/go-autorest/autorest/adal"
	"github.com/golang/glog"
)

// Client represents authentication details and cloud specific parameters for
// Azure Resource Manager clients.
type Client struct {
	Authentication   *Authentication
	BaseURI          string
	HTTPClient       *http.Client
	BearerAuthorizer *BearerAuthorizer
}

// BearerAuthorizer implements the bearer authorization.
type BearerAuthorizer struct {
	tokenProvider adal.OAuthTokenProvider
}

type userAgentTransport struct {
	userAgent string
	base      http.RoundTripper
	client    *Client
}

// newServicePrincipalTokenFromCredentials creates a new ServicePrincipalToken using values of the
// passed credentials map.
func newServicePrincipalTokenFromCredentials(auth *Authentication) (*adal.ServicePrincipalToken, error) {
	oauthConfig, err := adal.NewOAuthConfig(auth.ActiveDirectoryEndpoint, auth.TenantID)
	if err != nil {
		return nil, fmt.Errorf("creating the OAuth config: %v", err)
	}

	var useManagedIdentityExtension bool
	if len(auth.UseManagedIdentityExtension) > 0 {
		useManagedIdentityExtension, err = strconv.ParseBool(auth.UseManagedIdentityExtension)
		if err != nil {
			return nil, err
		}
	}

	if useManagedIdentityExtension {
		glog.V(2).Infoln("azure: using managed identity extension to retrieve access token")
		msiEndpoint, err := adal.GetMSIVMEndpoint()
		if err != nil {
			return nil, fmt.Errorf("Getting the managed service identity endpoint: %v", err)
		}
		return adal.NewServicePrincipalTokenFromMSI(
			msiEndpoint,
			auth.ResourceManagerEndpoint)
	}

	if len(auth.ClientSecret) > 0 {
		glog.V(2).Infoln("azure: using client_id+client_secret to retrieve access token")
		return adal.NewServicePrincipalToken(
			*oauthConfig,
			auth.ClientID,
			auth.ClientSecret,
			auth.ResourceManagerEndpoint)
	}

	return nil, fmt.Errorf("No credentials provided for AAD application %s", auth.ClientID)
}

// NewClient creates a new Azure API client from an Authentication struct and BaseURI.
func NewClient(auth *Authentication, baseURI string, userAgent string) (*Client, error) {

	tp, err := newServicePrincipalTokenFromCredentials(auth)
	if err != nil {
		return nil, err
	}

	resource, err := getResourceForToken(auth, baseURI)
	if err != nil {
		return nil, fmt.Errorf("Getting resource for token failed: %v", err)
	}

	client := &Client{
		Authentication: auth,
		BaseURI:        resource,
	}

	client.BearerAuthorizer = &BearerAuthorizer{tokenProvider: tp}

	uat := userAgentTransport{
		base:      http.DefaultTransport,
		userAgent: userAgent,
		client:    client,
	}

	client.HTTPClient = &http.Client{
		Transport: uat,
	}

	return client, nil
}

func (t userAgentTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.base == nil {
		return nil, errors.New("RoundTrip: no Transport specified")
	}

	newReq := *req
	newReq.Header = make(http.Header)
	for k, vv := range req.Header {
		newReq.Header[k] = vv
	}

	// Add the user agent header.
	newReq.Header["User-Agent"] = []string{t.userAgent}

	// Add the content-type header.
	newReq.Header["Content-Type"] = []string{"application/json"}

	// Refresh the token if necessary
	// TODO: don't refresh the token everytime
	refresher, ok := t.client.BearerAuthorizer.tokenProvider.(adal.Refresher)
	if ok {
		if err := refresher.EnsureFresh(); err != nil {
			return nil, fmt.Errorf("Failed to refresh the authorization token for request to %s: %v", newReq.URL, err)
		}
	}

	// Add the authorization header.
	newReq.Header["Authorization"] = []string{fmt.Sprintf("Bearer %s", t.client.BearerAuthorizer.tokenProvider.OAuthToken())}

	return t.base.RoundTrip(&newReq)
}

func getResourceForToken(auth *Authentication, baseURI string) (string, error) {
	// Compare dafault base URI from the SDK to the endpoints from the public cloud
	// Base URI and token resource are the same string. This func finds the authentication
	// file field that matches the SDK base URI. The SDK defines the public cloud
	// endpoint as its default base URI
	if !strings.HasSuffix(baseURI, "/") {
		baseURI += "/"
	}
	switch baseURI {
	case PublicCloud.ServiceManagementEndpoint:
		return auth.ManagementEndpoint, nil
	case PublicCloud.ResourceManagerEndpoint:
		return auth.ResourceManagerEndpoint, nil
	case PublicCloud.ActiveDirectoryEndpoint:
		return auth.ActiveDirectoryEndpoint, nil
	case PublicCloud.GalleryEndpoint:
		return auth.GalleryEndpoint, nil
	case PublicCloud.GraphEndpoint:
		return auth.GraphResourceID, nil
	}
	return "", fmt.Errorf("baseURI provided %q not found in endpoints", baseURI)
}
