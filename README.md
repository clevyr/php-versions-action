# PHP Matrix Action

This action outputs a matrix with the current PHP versions. Useful in tandem with [docker/build-push-action](https://github.com/marketplace/actions/build-and-push-docker-images).

## Inputs

### `repo`

**Required** Docker repo to prepend to `extra_tags`.

## Outputs

### `matrix`

Matrix JSON to be used in another job.

## Example usage

```yaml
gen-matrix:
  name: Generate Matrix
  runs-on: ubuntu-latest
  outputs:
    matrix: ${{ steps.gen-matrix.outputs.matrix }}
  steps:
    - name: Generate Matrix
      uses: clevyr/php-matrix-action@v1
      id: gen-matrix
      with:
        repo: clevyr/php

build:
  name: Build PHP ${{ matrix.php_version }} Image
  runs-on: ubuntu-latest
  needs: [gen-matrix]
  strategy:
    matrix: ${{ fromJson(needs.gen-matrix.outputs.matrix) }}
  steps:
    [...]
```
