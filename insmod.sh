#!/bin/bash
adb push hwbreak.ko  /data/local/tmp/
adb shell  rmmod /data/local/tmp/hwbreak.ko
adb shell  insmod /data/local/tmp/hwbreak.ko
