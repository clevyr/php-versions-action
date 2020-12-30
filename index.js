(async () => {
    const core = require('@actions/core');
    const axios = require('axios');

    try {
        const now = new Date();

        // Download schedule json
        const phpScheduleUrl = 'https://www.php.net/releases/active.php';
        let {data} = await axios.get(phpScheduleUrl);

        // Flatten versions into an array
        data = Object.values(data).flatMap((value, key) => Object.keys(value));

        const repo = core.getInput('repo');
        const matrix = {"include": []};

        // Push entries to matrix
        for (const php_version of data) {
            let extra_tags = '';
            matrix.include.push({php_version, extra_tags});
        }

        // Mark last version as latest
        matrix.include[matrix.include.length - 1].extra_tags += `\n${repo}:latest`;

        core.setOutput('matrix', matrix);
    } catch (error) {
        core.setFailed(error.message);
    }
})();
