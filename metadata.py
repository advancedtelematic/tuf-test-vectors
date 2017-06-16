#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from os import path
from tuf_vectors import subclasses
from tuf_vectors.tuf import Tuf
from tuf_vectors.uptane import Uptane


def main():
    for sub in subclasses(Tuf):
        sub.write_meta()

    for sub in subclasses(Uptane):
        sub.write_meta()


if __name__ == '__main__':
    main()
