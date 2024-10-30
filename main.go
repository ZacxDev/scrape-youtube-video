package ytdownloader

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/kkdai/youtube/v2"
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
	client youtube.Client
}

// NewDownloader creates a new VideoDownloader instance
func NewDownloader() *VideoDownloader {
	return &VideoDownloader{
		client: youtube.Client{},
	}
}

// Download downloads a YouTube video with the given options
func (d *VideoDownloader) Download(videoURL string, options DownloadOptions, progressCb ProgressCallback) (string, error) {
	// Get video metadata
	video, err := d.client.GetVideo(videoURL)
	if err != nil {
		return "", fmt.Errorf("failed to get video info: %w", err)
	}

	// Use video title as filename if not specified
	filename := options.OutputFile
	if filename == "" {
		filename = sanitizeFilename(video.Title) + ".mp4"
	}

	// Set default quality if not specified
	if options.Quality == "" {
		options.Quality = "hd720"
	}

	// Set default output directory if not specified
	if options.OutputDir == "" {
		options.OutputDir = "."
	}

	outputPath := filepath.Join(options.OutputDir, filename)

	// Create output directory if it doesn't exist
	if err := os.MkdirAll(options.OutputDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create output directory: %w", err)
	}

	// Filter formats by quality
	video.FilterQuality(options.Quality)
	if len(video.Formats) == 0 {
		return "", fmt.Errorf("no formats found for quality: %s", options.Quality)
	}

	// Get the stream
	stream, size, err := d.client.GetStream(video, &video.Formats[0])
	if err != nil {
		return "", fmt.Errorf("failed to get video stream: %w", err)
	}
	defer stream.Close()

	// Create the output file
	file, err := os.Create(outputPath)
	if err != nil {
		return "", fmt.Errorf("failed to create output file: %w", err)
	}
	defer file.Close()

	// Download the video
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
