package cmd

import (
	"bufio"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/aaronsb/yay-friend/internal/yay"
)

// presentPackageSelection displays search results and handles user selection like yay
func presentPackageSelection(results []yay.PackageSearchResult) ([]string, error) {
	if len(results) == 0 {
		return nil, fmt.Errorf("no packages found")
	}

	// Sort results by repository preference (AUR last, like yay)
	sort.Slice(results, func(i, j int) bool {
		// AUR packages should come last (higher numbers)
		if results[i].Repository == "aur" && results[j].Repository != "aur" {
			return false
		}
		if results[i].Repository != "aur" && results[j].Repository == "aur" {
			return true
		}
		// Same repository, sort by name
		return results[i].Name < results[j].Name
	})

	// Display results in yay format (reverse order like yay)
	fmt.Println()
	for i := len(results) - 1; i >= 0; i-- {
		result := results[i]
		num := i + 1
		
		// Format like yay: "20 aur/package-name version (votes popularity)"
		repoName := fmt.Sprintf("%s/%s", result.Repository, result.Name)
		
		fmt.Printf("%d %s %s %s\n", num, repoName, result.Version, result.Info)
		
		// Print description indented
		if result.Description != "" {
			fmt.Printf("    %s\n", result.Description)
		}
	}

	// Prompt for selection
	fmt.Printf("==> Packages to install (eg: 1 2 3, 1-3 or ^4)\n")
	fmt.Printf("==> ")

	// Read user input
	reader := bufio.NewReader(os.Stdin)
	input, err := reader.ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("failed to read input: %w", err)
	}

	inputStr := strings.TrimSpace(input)
	if inputStr == "" {
		return nil, fmt.Errorf("no selection made")
	}

	// Handle Ctrl+C representation (^C) 
	if strings.HasPrefix(inputStr, "^") {
		return nil, fmt.Errorf("selection cancelled")
	}

	// Parse selection
	selectedIndices, err := parseSelection(inputStr, len(results))
	if err != nil {
		return nil, fmt.Errorf("invalid selection: %w", err)
	}

	// Convert indices to package names
	var selectedPackages []string
	for _, idx := range selectedIndices {
		if idx >= 0 && idx < len(results) {
			selectedPackages = append(selectedPackages, results[idx].Name)
		}
	}

	return selectedPackages, nil
}

// parseSelection parses user selection string like "1 2 3", "1-3", "^4", etc.
func parseSelection(input string, maxCount int) ([]int, error) {
	var indices []int
	
	// Handle exclusion (^4 means "all except 4")
	if strings.HasPrefix(input, "^") {
		excludeStr := strings.TrimPrefix(input, "^")
		excludeIndices, err := parseSelectionPart(excludeStr, maxCount)
		if err != nil {
			return nil, err
		}
		
		// Add all indices except excluded ones
		excludeMap := make(map[int]bool)
		for _, idx := range excludeIndices {
			excludeMap[idx] = true
		}
		
		for i := 0; i < maxCount; i++ {
			if !excludeMap[i] {
				indices = append(indices, i)
			}
		}
		
		return indices, nil
	}

	// Parse normal selection
	parts := strings.Fields(input)
	for _, part := range parts {
		partIndices, err := parseSelectionPart(part, maxCount)
		if err != nil {
			return nil, err
		}
		indices = append(indices, partIndices...)
	}

	// Remove duplicates and sort
	indexMap := make(map[int]bool)
	for _, idx := range indices {
		indexMap[idx] = true
	}
	
	indices = make([]int, 0, len(indexMap))
	for idx := range indexMap {
		indices = append(indices, idx)
	}
	sort.Ints(indices)

	return indices, nil
}

// parseSelectionPart parses a single part like "3", "1-5", etc.
func parseSelectionPart(part string, maxCount int) ([]int, error) {
	var indices []int

	if strings.Contains(part, "-") {
		// Range selection like "1-5"
		rangeParts := strings.Split(part, "-")
		if len(rangeParts) != 2 {
			return nil, fmt.Errorf("invalid range format: %s", part)
		}

		start, err := strconv.Atoi(rangeParts[0])
		if err != nil {
			return nil, fmt.Errorf("invalid start number: %s", rangeParts[0])
		}

		end, err := strconv.Atoi(rangeParts[1])
		if err != nil {
			return nil, fmt.Errorf("invalid end number: %s", rangeParts[1])
		}

		if start < 1 || end > maxCount || start > end {
			return nil, fmt.Errorf("invalid range: %d-%d (max: %d)", start, end, maxCount)
		}

		for i := start; i <= end; i++ {
			indices = append(indices, i-1) // Convert to 0-based
		}
	} else {
		// Single number
		num, err := strconv.Atoi(part)
		if err != nil {
			return nil, fmt.Errorf("invalid number: %s", part)
		}

		if num < 1 || num > maxCount {
			return nil, fmt.Errorf("number out of range: %d (max: %d)", num, maxCount)
		}

		indices = append(indices, num-1) // Convert to 0-based
	}

	return indices, nil
}