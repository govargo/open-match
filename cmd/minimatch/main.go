// Copyright 2019 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package main is the minimatch in-process testing binary for Open Match.
package main

import (
	"context"

	"open-match.dev/open-match/internal/app/minimatch"
	"open-match.dev/open-match/internal/appmain"
)

func main() {
	ctx := context.Background()
	appmain.RunApplication(ctx, "minimatch", minimatch.BindService)
}
