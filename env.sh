export PATH=$PATH:/aosp/prebuilts/gcc/linux-x86/aarch64/aarch64-linux-android-4.9/bin
export ARCH=arm64
export CROSS_COMPILE=aarch64-linux-android-


cd /aosp
source build/envsetup.sh 
lunch 25
cd -

