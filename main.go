package ytdownloader

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/kkdai/youtube/v2"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/option"
	youtube_api "google.golang.org/api/youtube/v3"
)

// DownloadOptions contains configuration for the video download
type DownloadOptions struct {
	OutputDir  string
	OutputFile string
	Quality    string
}

// ProgressCallback is called periodically during download with progress updates
type ProgressCallback func(downloadedBytes, totalBytes int64, progress float64)

// VideoDownloader handles YouTube video downloads
type VideoDownloader struct {
	client         youtube.Client
	oauthConfig    *oauth2.Config
	oauthToken     *oauth2.Token
	youtubeService *youtube_api.Service
}

// OAuthCredentials contains OAuth2 client credentials
type OAuthCredentials struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	RedirectURL  string `json:"redirect_uri"`
}

type OAuthConfigJSON struct {
	Web struct {
		ClientID     string   `json:"client_id"`
		ProjectID    string   `json:"project_id"`
		AuthURI      string   `json:"auth_uri"`
		TokenURI     string   `json:"token_uri"`
		ClientSecret string   `json:"client_secret"`
		RedirectURIs []string `json:"redirect_uris"`
	} `json:"web"`
	Installed struct {
		ClientID     string   `json:"client_id"`
		ProjectID    string   `json:"project_id"`
		AuthURI      string   `json:"auth_uri"`
		TokenURI     string   `json:"token_uri"`
		ClientSecret string   `json:"client_secret"`
		RedirectURIs []string `json:"redirect_uris"`
	} `json:"installed"`
}

// NewDownloader creates a new VideoDownloader instance with OAuth2 configuration
func NewDownloader(credentialsFile string) (*VideoDownloader, error) {
	// Read OAuth credentials from file
	credsFile, err := os.ReadFile(credentialsFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read credentials file: %w", err)
	}

	// Parse the credentials JSON
	var configJSON OAuthConfigJSON
	if err := json.Unmarshal(credsFile, &configJSON); err != nil {
		return nil, fmt.Errorf("failed to parse credentials: %w", err)
	}

	// Determine if we're using web or installed app credentials
	var clientID, clientSecret string
	if configJSON.Web.ClientID != "" {
		clientID = configJSON.Web.ClientID
		clientSecret = configJSON.Web.ClientSecret
	} else {
		clientID = configJSON.Installed.ClientID
		clientSecret = configJSON.Installed.ClientSecret
	}

	config := &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  "urn:ietf:wg:oauth:2.0:oob", // Standard redirect URI for CLI applications
		Scopes: []string{
			youtube_api.YoutubeReadonlyScope,
		},
		Endpoint: google.Endpoint,
	}

	return &VideoDownloader{
		client:      youtube.Client{},
		oauthConfig: config,
	}, nil
}

// Authenticate performs OAuth2 authentication and stores the token
func (d *VideoDownloader) Authenticate(ctx context.Context, authCode string) error {
	token, err := d.oauthConfig.Exchange(ctx, authCode)
	if err != nil {
		return fmt.Errorf("failed to exchange auth code: %w", err)
	}

	d.oauthToken = token

	// Initialize YouTube API service
	youtubeService, err := youtube_api.NewService(ctx,
		option.WithTokenSource(d.oauthConfig.TokenSource(ctx, token)))
	if err != nil {
		return fmt.Errorf("failed to create YouTube service: %w", err)
	}

	d.youtubeService = youtubeService
	return nil
}

// SaveToken saves the OAuth token to a file for future use
func (d *VideoDownloader) SaveToken(tokenFile string) error {
	if d.oauthToken == nil {
		return fmt.Errorf("no token available to save")
	}

	tokenJson, err := json.Marshal(d.oauthToken)
	if err != nil {
		return fmt.Errorf("failed to marshal token: %w", err)
	}

	return os.WriteFile(tokenFile, tokenJson, 0600)
}

// LoadToken loads a previously saved OAuth token
func (d *VideoDownloader) LoadToken(ctx context.Context, tokenFile string) error {
	tokenData, err := os.ReadFile(tokenFile)
	if err != nil {
		return fmt.Errorf("failed to read token file: %w", err)
	}

	var token oauth2.Token
	if err := json.Unmarshal(tokenData, &token); err != nil {
		return fmt.Errorf("failed to parse token: %w", err)
	}

	d.oauthToken = &token

	// Initialize YouTube API service
	youtubeService, err := youtube_api.NewService(ctx,
		option.WithTokenSource(d.oauthConfig.TokenSource(ctx, &token)))
	if err != nil {
		return fmt.Errorf("failed to create YouTube service: %w", err)
	}

	d.youtubeService = youtubeService
	return nil
}

// GetAuthURL returns the OAuth2 authorization URL
func (d *VideoDownloader) GetAuthURL() string {
	return d.oauthConfig.AuthCodeURL("state")
}

// Download downloads a YouTube video with the given options
func (d *VideoDownloader) Download(videoURL string, options DownloadOptions, progressCb ProgressCallback) (string, error) {
	if d.youtubeService == nil {
		return "", fmt.Errorf("YouTube service not initialized. Please authenticate first")
	}

	// Get video metadata
	video, err := d.client.GetVideo(videoURL)
	if err != nil {
		return "", fmt.Errorf("failed to get info for video %s: %w", videoURL, err)
	}

	// Rest of the download function remains the same
	filename := options.OutputFile
	if filename == "" {
		filename = sanitizeFilename(video.Title) + ".mp4"
	}

	if options.Quality == "" {
		options.Quality = "hd720"
	}

	if options.OutputDir == "" {
		options.OutputDir = "."
	}

	outputPath := filepath.Join(options.OutputDir, filename)

	if err := os.MkdirAll(options.OutputDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create output directory: %w", err)
	}

	video.FilterQuality(options.Quality)
	if len(video.Formats) == 0 {
		return "", fmt.Errorf("no formats found for quality: %s", options.Quality)
	}

	stream, size, err := d.client.GetStream(video, &video.Formats[0])
	if err != nil {
		return "", fmt.Errorf("failed to get video stream: %w", err)
	}
	defer stream.Close()

	file, err := os.Create(outputPath)
	if err != nil {
		return "", fmt.Errorf("failed to create output file: %w", err)
	}
	defer file.Close()

	var downloaded int64
	buffer := make([]byte, 1024*1024) // 1MB buffer
	for {
		n, err := stream.Read(buffer)
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", fmt.Errorf("error reading stream: %w", err)
		}
		_, err = file.Write(buffer[:n])
		if err != nil {
			return "", fmt.Errorf("error writing to file: %w", err)
		}
		downloaded += int64(n)
		if progressCb != nil {
			progress := float64(downloaded) / float64(size) * 100
			progressCb(downloaded, size, progress)
		}
	}

	return outputPath, nil
}

// sanitizeFilename removes or replaces invalid characters in filenames
func sanitizeFilename(name string) string {
	invalid := []string{"/", "\\", ":", "*", "?", "\"", "<", ">", "|"}
	result := name
	for _, char := range invalid {
		result = strings.ReplaceAll(result, char, "_")
	}
	return result
}
