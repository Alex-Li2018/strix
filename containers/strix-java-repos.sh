#!/bin/bash
# Render Maven/Gradle private-mirror configuration from environment variables
# (set on `docker run` and forwarded into sandboxes by the orchestrator):
#
#   MAVEN_MIRROR_URL   base URL of the private repository, e.g.
#                      https://nexus.corp.example/repository/maven-public/
#   MAVEN_MIRROR_ID    server id used to pair credentials (default: strix-mirror)
#   MAVEN_MIRROR_USER  optional username
#   MAVEN_MIRROR_PASS  optional password
#   GRADLE_MIRROR_URL  optional separate Gradle mirror; defaults to MAVEN_MIRROR_URL
#
# Writes ~/.m2/settings.xml (mirrorOf external:* — local/file repos untouched)
# and ~/.gradle/init.gradle (dependencies + plugin repositories). Idempotent:
# re-running overwrites both files. Runs as the invoking user.
set -e

M2_SETTINGS="${HOME}/.m2/settings.xml"
GRADLE_INIT="${HOME}/.gradle/init.gradle"

maven_url="${MAVEN_MIRROR_URL:-}"
gradle_url="${GRADLE_MIRROR_URL:-${maven_url}}"
mirror_id="${MAVEN_MIRROR_ID:-strix-mirror}"
mirror_user="${MAVEN_MIRROR_USER:-}"
mirror_pass="${MAVEN_MIRROR_PASS:-}"

# Minimal XML escaping so URLs/credentials with &, <, > can't break the file.
_xml_escape() {
  printf '%s' "$1" | sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g' \
    -e 's/"/\&quot;/g' -e "s/'/\&apos;/g"
}

# Groovy single-quoted strings only treat \' specially; escape backslashes too.
_groovy_escape() {
  printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e "s/'/\\\\'/g"
}

if [ -n "$maven_url" ]; then
  mkdir -p "$(dirname "$M2_SETTINGS")"
  esc_url="$(_xml_escape "$maven_url")"
  esc_id="$(_xml_escape "$mirror_id")"
  {
    echo '<?xml version="1.0" encoding="UTF-8"?>'
    echo '<settings xmlns="http://maven.apache.org/SETTINGS/1.2.0">'
    echo '  <mirrors>'
    echo '    <mirror>'
    echo "      <id>${esc_id}</id>"
    echo '      <name>Private mirror</name>'
    echo "      <url>${esc_url}</url>"
    echo '      <mirrorOf>external:*</mirrorOf>'
    echo '    </mirror>'
    echo '  </mirrors>'
    if [ -n "$mirror_user" ]; then
      esc_user="$(_xml_escape "$mirror_user")"
      esc_pass="$(_xml_escape "$mirror_pass")"
      echo '  <servers>'
      echo '    <server>'
      echo "      <id>${esc_id}</id>"
      echo "      <username>${esc_user}</username>"
      echo "      <password>${esc_pass}</password>"
      echo '    </server>'
      echo '  </servers>'
    fi
    echo '</settings>'
  } > "$M2_SETTINGS"
  echo "Maven mirror configured: ${maven_url}"
fi

if [ -n "$gradle_url" ]; then
  mkdir -p "$(dirname "$GRADLE_INIT")"
  g_url="$(_groovy_escape "$gradle_url")"
  g_user="$(_groovy_escape "$mirror_user")"
  g_pass="$(_groovy_escape "$mirror_pass")"
  {
    echo 'allprojects {'
    echo '    repositories {'
    echo "        maven { url '${g_url}'"
    if [ -n "$mirror_user" ]; then
      echo "            credentials { username '${g_user}'; password '${g_pass}' }"
    fi
      echo '        }'
    echo '    }'
    echo '}'
    echo 'settingsEvaluated { settings ->'
    echo '    settings.pluginManagement {'
    echo '        repositories {'
    echo "            maven { url '${g_url}'"
    if [ -n "$mirror_user" ]; then
      echo "                credentials { username '${g_user}'; password '${g_pass}' }"
    fi
      echo '            }'
    echo '        }'
    echo '    }'
    echo '}'
  } > "$GRADLE_INIT"
  echo "Gradle mirror configured: ${gradle_url}"
fi

if [ -z "$maven_url" ] && [ -z "$gradle_url" ]; then
  echo "No MAVEN_MIRROR_URL/GRADLE_MIRROR_URL set; using default repositories."
fi
