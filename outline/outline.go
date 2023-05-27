package outline_lib

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

type AccessKey struct {
	Id        string `json:"id"`
	Name      string `json:"name"`
	Password  string `json:"password"`
	Port      int    `json:"port"`
	Method    string `json:"method"`
	AccessUrl string `json:"accessUrl"`
}

type AccessKeysResponse struct {
	AccessKeys []AccessKey `json:"accessKeys"`
}

type Client struct {
	ApiUrl               string
	httpClient           *http.Client
	accessKeysCache      []AccessKey
	transferredDataCache map[string]int64
}

type MetricsResponse struct {
	MetricsEnabled bool `json:"metricsEnabled"`
}

type Server struct {
	ApiUrl     string
	CertSha256 string
	ServerInfo []ServerResponse
}

type ServerResponse struct {
	Name                  string `json:"name"`
	ServerId              string `json:"serverId"`
	MetricsEnabled        bool   `json:"metricsEnabled"`
	CreatedTimestampMs    int64  `json:"createdTimestampMs"`
	Version               string `json:"version"`
	PortForNewAccessKeys  int    `json:"portForNewAccessKeys"`
	HostnameForAccessKeys string `json:"hostnameForAccessKeys"`
}

type TransferData struct {
	BytesTransferredByUserId map[string]int64 `json:"bytesTransferredByUserId"`
}

const contentTypeJSON = "application/json"

var jsonHeader = map[string]string{"Content-Type": contentTypeJSON}

// NewClient returns a new instance of the Client
func NewClient(apiURL string) *Client {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		MaxIdleConns:        20,
		IdleConnTimeout:     20 * time.Second,
		TLSHandshakeTimeout: 20 * time.Second,
	}

	return &Client{
		ApiUrl: apiURL,
		httpClient: &http.Client{
			Transport: tr,
		},
	}
}

// MakeRequest makes requests to server
func (c *Client) MakeRequest(ctx context.Context, method, endpoint string, headers map[string]string, body io.Reader) (*http.Response, error) {
	fullURL := c.ApiUrl + endpoint

	req, err := http.NewRequestWithContext(ctx, method, fullURL, body)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	for key, value := range headers {
		req.Header.Set(key, value)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute request: %w", err)
	}

	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("server responded with code %d", resp.StatusCode)
	}

	return resp, nil
}

func parseJSONFromReader(r io.Reader, v interface{}) error {
	if r == nil {
		return errors.New("reader is nil")
	}

	decoder := json.NewDecoder(r)
	return decoder.Decode(v)
}

func (c *Client) GetServerInfo() (result ServerResponse, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := c.MakeRequest(ctx, "GET", "/server", map[string]string{"content-type": contentTypeJSON}, nil)
	if err != nil {
		return ServerResponse{}, err
	}

	err = parseJSONFromReader(resp.Body, &result)
	if err != nil {
		return ServerResponse{}, err
	}

	return
}

func (c *Client) ChangeHostname(hostname string) (bool, error) {
	return c.sendPutRequest("/server/hostname-for-access-keys", map[string]string{"hostname": hostname})
}

func (c *Client) RenameServer(name string) (bool, error) {
	return c.sendPutRequest("/name", map[string]string{"name": name})
}

func (c *Client) CheckMetrics() (result MetricsResponse, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	resp, err := c.MakeRequest(ctx, "GET", "/metrics/enabled", map[string]string{"content-type": contentTypeJSON}, nil)
	if err != nil {
		return MetricsResponse{}, err
	}

	err = parseJSONFromReader(resp.Body, &result)
	return
}

func (c *Client) ChangeMetrics(flag bool) (bool, error) {
	return c.sendPutRequest("/metrics/enabled", map[string]bool{"metricsEnabled": flag})
}

func (c *Client) ChangeDefaultPort(port int) (bool, error) {
	return c.sendPutRequest("/server/port-for-new-access-keys", map[string]int{"port": port})
}

func (c *Client) SetDataLimitAllKeys(limit int64) (bool, error) {
	return c.sendPutRequest("/server/access-key-data-limit", map[string]map[string]int64{"limit": {"bytes": limit}})
}

func (c *Client) DeleteAllDataLimits() (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	resp, err := c.MakeRequest(ctx, "DELETE", "/server/access-key-data-limit", map[string]string{}, nil)
	if err != nil {
		return false, fmt.Errorf("failed to delete all data limits: %w", err)
	}

	if resp.StatusCode == http.StatusNoContent {
		return true, nil
	}

	return false, err
}

func (c *Client) CreateAccessKey() (result AccessKey, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	data := map[string]string{"method": "aes-192-gcm"}
	byteData, err := json.Marshal(data)

	resp, err := c.MakeRequest(ctx, "POST", "/access-keys", map[string]string{"content-type": contentTypeJSON}, bytes.NewBuffer(byteData))
	if err != nil {
		return result, err
	}

	err = parseJSONFromReader(resp.Body, &result)
	return
}

func (c *Client) GetListAccessKeys() (result AccessKeysResponse, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if ctx.Err() != nil {
		return result, fmt.Errorf("request timed out: %w", ctx.Err())
	}

	resp, err := c.MakeRequest(ctx, "GET", "/access-keys", map[string]string{"content-type": contentTypeJSON}, nil)
	if err != nil {
		return result, err
	}

	err = parseJSONFromReader(resp.Body, &result)
	return
}

func (c *Client) DeleteAccessKey(id string) (bool, error) {
	return c.sendDeleteRequest("/access-keys/" + id)
}

func (c *Client) RenameAccessKey(id int, name string) (bool, error) {
	return c.sendPutRequest(fmt.Sprintf("/access-keys/%d/name", id), map[string]string{"name": name})
}

func (c *Client) SetDataLimitAccessKey(id int, limit int64) (bool, error) {
	return c.sendPutRequest(fmt.Sprintf("/access-keys/%d/data-limit", id), map[string]map[string]int64{"limit": {"bytes": limit}})
}

func (c *Client) DeleteDataLimitAccessKey(id int) (bool, error) {
	return c.sendDeleteRequest(fmt.Sprintf("/access-keys/%d/data-limit", id))
}

func (c *Client) DataTransferredAccessKey() (result TransferData, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	resp, err := c.MakeRequest(ctx, "GET", "/metrics/transfer", map[string]string{"content-type": contentTypeJSON}, nil)
	if err != nil {
		return result, err
	}

	err = parseJSONFromReader(resp.Body, &result)
	return
}

// Functions for sending PUT and DELETE requests
func (c *Client) sendPutRequest(endpoint string, data interface{}) (bool, error) {
	byteData, err := json.Marshal(data)
	if err != nil {
		return false, fmt.Errorf("failed to marshal data: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	resp, err := c.MakeRequest(ctx, http.MethodPut, endpoint, jsonHeader, bytes.NewBuffer(byteData))
	if err != nil {
		return false, fmt.Errorf("failed to send PUT request: %w", err)
	}

	return resp.StatusCode == http.StatusOK, nil
}

func (c *Client) sendDeleteRequest(endpoint string) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	resp, err := c.MakeRequest(ctx, http.MethodDelete, endpoint, jsonHeader, nil)
	if err != nil {
		return false, fmt.Errorf("failed to send DELETE request: %w", err)
	}

	return resp.StatusCode == http.StatusNoContent, nil
}
