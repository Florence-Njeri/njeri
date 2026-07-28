# Auditing Github ACtions With Zizmor

## Artifacts

In **GitHub Actions**, *artifacts* are files produced during a workflow run that you want to keep or use elsewhere i.e the runtime artifacts(generated and published buy the workflow) and workflow artifacts (passed on between workflows using the `upload-artifact` and `download-artifact`)

## Cache Poisoning
`actions/setup-node` caches your node_modules and the npm cache between runs to speed up npm ci. The cache is keyed on `package-lock.json`.

*Cache poisoning* matters more when the workflow is a release one since it produces artifacts that go to **npm**, **GitHub Releases**, or to **Docker Hub** and shipped to every user of your package

The fix  is to add a `cache: '`' which  forces `npm ci` to always hit the npm registry directly which is slower but guarantees clean packages are installed for every release build.