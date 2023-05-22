package pkg

import (
	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

func syftProvider(userInput string, config ProviderConfig) ([]Package, Context, *sbom.SBOM, error) {
	log.Log.Info("Line 11s")
	memoryConsumption()

	if config.CatalogingOptions.Search.Scope == "" {
		return nil, Context{}, nil, errDoesNotProvide
	}

	sourceInput, err := source.ParseInputWithName(userInput, config.Platform, config.Name, config.DefaultImagePullSource)
	if err != nil {
		return nil, Context{}, nil, err
	}

	log.Log.Info("Line 23s")
	memoryConsumption()

	src, cleanup, err := source.New(*sourceInput, config.RegistryOptions, config.Exclusions)
	if err != nil {
		return nil, Context{}, nil, err
	}
	log.Log.Info("Line 30s")
	memoryConsumption()
	defer cleanup()

	catalog, relationships, theDistro, err := syft.CatalogPackages(src, config.CatalogingOptions)
	if err != nil {
		return nil, Context{}, nil, err
	}
	log.Log.Info("Line 38s")
	memoryConsumption()

	catalog = removePackagesByOverlap(catalog, relationships)
	log.Log.Info("Line 42s")
	memoryConsumption()

	packages := FromCollection(catalog, config.SynthesisConfig)
	log.Log.Info("Line 46s")
	memoryConsumption()
	context := Context{
		Source: &src.Metadata,
		Distro: theDistro,
	}

	sbom := &sbom.SBOM{
		Source:        src.Metadata,
		Relationships: relationships,
		Artifacts: sbom.Artifacts{
			Packages: catalog,
		},
	}

	return packages, context, sbom, nil
}
