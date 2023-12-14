/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/
package docs

const (
	ThreagileVersion = "1.0.0" // Also update into example and stub model files and openapi.yaml
	Logo             = "  _____ _                          _ _      \n |_   _| |__  _ __ ___  __ _  __ _(_) | ___ \n   | | | '_ \\| '__/ _ \\/ _` |/ _` | | |/ _ \\\n   | | | | | | | |  __/ (_| | (_| | | |  __/\n   |_| |_| |_|_|  \\___|\\__,_|\\__, |_|_|\\___|\n                             |___/        " +
		"\nThreagile - Agile Threat Modeling"
	VersionText = "Documentation: https://threagile.io\n" +
		"Docker Images: https://hub.docker.com/r/threagile/threagile\n" +
		"Sourcecode: https://github.com/threagile\n" +
		"License: Open-Source (MIT License)" +
		"Version: " + ThreagileVersion // TODO: add buildTimestamp + " (" + buildTimestamp + ")"
	Examples = "Examples:\n\n" +
		"If you want to create an example model (via docker) as a starting point to learn about Threagile just run: \n" +
		" docker run --rm -it -v \"$(pwd)\":app/work threagile/threagile -create-example-model -output app/work \n\n" +
		"If you want to create a minimal stub model (via docker) as a starting point for your own model just run: \n" +
		" docker run --rm -it -v \"$(pwd)\":app/work threagile/threagile -create-stub-model -output app/work \n\n" +
		"If you want to execute Threagile on a model yaml file (via docker):  \n" +
		" docker run --rm -it -v \"$(pwd)\":app/work threagile/threagile -verbose -model -output app/work \n\n" +
		"If you want to run Threagile as a server (REST API) on some port (here 8080):  \n" +
		" docker run --rm -it --shm-size=256m  -p 8080:8080 --name --mount 'type=volume,src=threagile-storage,dst=/data,readonly=false' threagile/threagile -server 8080 \n\n" +
		"If you want to find out about the different enum values usable in the model yaml file: \n" +
		" docker run --rm -it threagile/threagile -list-types\n\n" +
		"If you want to use some nice editing help (syntax validation, autocompletion, and live templates) in your favourite IDE: " +
		" docker run --rm -it -v \"$(pwd)\":app/work threagile/threagile -create-editing-support -output app/work\n\n" +
		"If you want to list all available model macros (which are macros capable of reading a model yaml file, asking you questions in a wizard-style and then update the model yaml file accordingly): \n" +
		" docker run --rm -it threagile/threagile -list-model-macros \n\n" +
		"If you want to execute a certain model macro on the model yaml file (here the macro add-build-pipeline): \n" +
		" docker run --rm -it -v \"$(pwd)\":app/work threagile/threagile -model app/work/threagile.yaml -output app/work -execute-model-macro add-build-pipeline"
)
