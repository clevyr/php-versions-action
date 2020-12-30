(async () => {
    const core = require('@actions/core');
    const axios = require('axios');
    const semver = require('semver')

    try {
        // Download schedule json
        const phpScheduleUrl = 'https://www.php.net/releases/active.php';
        let {data} = await axios.get(phpScheduleUrl);

        // Flatten versions into an array
        data = Object.values(data).flatMap((value) => Object.keys(value));
        const maxMajorVersions = data.reduce((acc, version) => {
            let major = semver.major(semver.coerce(version));
            if (!(major in acc) || semver.lt(semver.coerce(acc[major]), semver.coerce(version))) {
                acc[major] = version;
            }
            return acc;
        }, {});

        const repo = core.getInput('repo');
        const matrix = {"include": []};

        // Push entries to matrix
        for (const php_version of data) {
            let extra_tags = '';
            if (Object.values(maxMajorVersions).includes(php_version)) {
                extra_tags += `\n${semver.major(semver.coerce(php_version))}`;
            }
            matrix.include.push({php_version, extra_tags});
        }

        // Mark last version as latest
        matrix.include[matrix.include.length - 1].extra_tags += `\n${repo}:latest`;

        core.setOutput('matrix', matrix);
    } catch (error) {
        console.error(error)
        core.setFailed(error.message);
    }
})();
