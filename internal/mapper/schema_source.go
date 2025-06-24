/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package mapper

import (
	"context"
	"fmt"
	"os"
)

type SchemaSource interface {
	// GetSchema returns the schema as a string
	GetSchema(ctx context.Context) (string, error)
}

// FileSchemaSource loads schema from a file on disk
// If FilePath is empty, uses the default path "config/ksl/schema.zed"
type FileSchemaSource struct {
	FilePath string
}

// Returns the schema as a string from the file specified in FilePath.
// If FilePath is empty, it defaults to "config/ksl/schema.zed".
func (f *FileSchemaSource) GetSchema(ctx context.Context) (string, error) {
	filePath := f.FilePath
	if filePath == "" {
		filePath = "config/ksl/schema.zed"
	}

	schemaBytes, err := os.ReadFile(filePath)
	if err != nil {
		return "", fmt.Errorf("unable to read schema file %s: %w", filePath, err)
	}
	return string(schemaBytes), nil
}
