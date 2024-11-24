# Contributing

## Workflow

MongoDB welcomes community contributions! If you’re interested in making a contribution to the MongoDB Shell, please follow the steps below before you start writing any code:

1. Sign the [contributor's agreement](https://www.mongodb.com/contributor). This will allow us to review and accept contributions.
1. Fork the repository on GitHub
1. Create a branch with a name that briefly describes your feature
1. Implement your feature or bug fix
1. Add new test cases that verify your bug fix or make sure no one
   unintentionally breaks your feature in the future and run them with `npm test`
   - You can use `it.only()` instead of `it()` in mocha tests to run only a subset of tests.
     This can be helpful, because running the full test suite likely takes some time.
1. Add comments around your new code that explain what's happening
1. Commit and push your changes to your branch then submit a pull request

## Bugs

You can report new bugs by
[creating a new issue](https://github.com/mongodb-js/oidc-plugin/issues).
Please include as much information as possible about your environment.

## Releasing

To release a new version of this plugin, follow these steps:

1. Run the [Prepare Release](https://github.com/mongodb-js/oidc-plugin/actions/workflows/prepare-release.yml) workflow with the desired type of version bump (major, minor, patch) or an exact version.
1. The workflow will create a new release branch and a new pull request with the changes. Review the changes and ensure everything on CI looks good.
1. Run the [Publish Release](https://github.com/mongodb-js/oidc-plugin/actions/workflows/publish-release.yml) workflow from the release branch. This will publish the plugin to npm, merge the release PR, and create a new github release.
