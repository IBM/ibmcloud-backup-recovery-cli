#!/bin/bash

# this script processes the generated translations for embedding

print_usage () {
    echo "
This script merges generated translation files. By default, existing fields 'win' any collisions.

usage:
   ./prepare-translations.sh [-u/--update-existing]

where:
   -u/--update-existing: values from the newly generated file 'win' any collisions
"
}

# Parse flags and arguments
while getopts 'h:u' flag; do
  case "${flag}" in
    u) UPDATE_EXISTING=1 ;;
    h|*) print_usage
        exit 1 ;;
  esac
done

# Merge generated translation files together, if they exist.

# note that `en-us` isn't the proper locale format but it's what the generator produces.
# this is a temporary file so it doesn't matter - the correct format will be used in the end
for filename in i18n/resources/*.en-us.all.json; do
    [ -e "$filename" ] || continue

    final_resource_file="i18n/resources/all.en_US.json"

    # if there isn't already a base file, just rename the current file to create one
    if [ ! -f "$final_resource_file" ]; then
        mv "$filename" "$final_resource_file"
        continue
    fi

    # by default, only add the fields with "id" properties that are not already present
    # (the existing fields "win" any collisions)
    priority_file="$final_resource_file"
    secondary_file="$filename"

    # if the user needs to update existing values in the resource file with newly generated files,
    # they can specify this argument to switch the priority order between the files
    if [[ "$UPDATE_EXISTING" -eq 1 ]]; then
        priority_file="$filename"
        secondary_file="$final_resource_file"
    fi

    # connecting these lines with && because i dont want them to execute unless the preceding command executed properly
    # this command will merge together the translation files
    jq -s 'add | unique_by(.id)' "$priority_file" "$secondary_file" > "$final_resource_file".temp && \
      cp "$final_resource_file".temp "$final_resource_file" && \
      rm "$final_resource_file".temp && \
      rm "$filename"
done
