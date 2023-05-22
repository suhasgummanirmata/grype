package pkg

import (
	"errors"
	"fmt"
	"runtime"

	"github.com/bmatcuk/doublestar/v2"

	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

func memoryConsumption() {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	log.Log.Info(fmt.Sprintf("Allocated memory: %v bytes\n", m.Alloc))
}

var errDoesNotProvide = fmt.Errorf("cannot provide packages from the given source")

// Provide a set of packages and context metadata describing where they were sourced from.
func Provide(userInput string, config ProviderConfig) ([]Package, Context, *sbom.SBOM, error) {
	log.Log.Info("Line 25")
	memoryConsumption()

	packages, ctx, s, err := syftSBOMProvider(userInput, config)
	log.Log.Info(userInput)
	log.Log.Info("Line 29")
	memoryConsumption()

	if !errors.Is(err, errDoesNotProvide) {
		if len(config.Exclusions) > 0 {
			packages, err = filterPackageExclusions(packages, config.Exclusions)
			log.Log.Info("Line 35")
			memoryConsumption()
			if err != nil {
				return nil, ctx, s, err
			}
		}
		return packages, ctx, s, err
	}

	packages, ctx, err = purlProvider(userInput)
	log.Log.Info("Line 45")
	memoryConsumption()
	if !errors.Is(err, errDoesNotProvide) {
		return packages, ctx, s, err
	}

	p, c, s, e := syftProvider(userInput, config)

	log.Log.Info("Line 53")
	memoryConsumption()

	return p, c, s, e
}

// This will filter the provided packages list based on a set of exclusion expressions. Globs
// are allowed for the exclusions. A package will be *excluded* only if *all locations* match
// one of the provided exclusions.
func filterPackageExclusions(packages []Package, exclusions []string) ([]Package, error) {
	var out []Package
	for _, pkg := range packages {
		includePackage := true
		locations := pkg.Locations.ToSlice()
		if len(locations) > 0 {
			includePackage = false
			// require ALL locations to be excluded for the package to be excluded
		location:
			for _, location := range locations {
				for _, exclusion := range exclusions {
					match, err := locationMatches(location, exclusion)
					if err != nil {
						return nil, err
					}
					if match {
						continue location
					}
				}
				// if this point is reached, one location has not matched any exclusion, include the package
				includePackage = true
				break
			}
		}
		if includePackage {
			out = append(out, pkg)
		}
	}
	return out, nil
}

// Test a location RealPath and VirtualPath for a match against the exclusion parameter.
// The exclusion allows glob expressions such as `/usr/**` or `**/*.json`. If the exclusion
// is an invalid pattern, an error is returned; otherwise, the resulting boolean indicates a match.
func locationMatches(location source.Location, exclusion string) (bool, error) {
	matchesRealPath, err := doublestar.Match(exclusion, location.RealPath)
	if err != nil {
		return false, err
	}
	matchesVirtualPath, err := doublestar.Match(exclusion, location.VirtualPath)
	if err != nil {
		return false, err
	}
	return matchesRealPath || matchesVirtualPath, nil
}
