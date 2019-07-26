#!/usr/bin/env bash

git fetch upstream
git rebase upstream/master
git push
