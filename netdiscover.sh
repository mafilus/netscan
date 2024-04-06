#!/bin/bash

ip neigh | grep -v -P '(FAILED|INCOMPLETE)'
  
