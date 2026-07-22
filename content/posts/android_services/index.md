---
title: "Pentesting Android Services"
description: "A beginner-friendly guide to Android Services as an attack surface, including bound vs unbound services, LocalBinders, Messenger IPC, and sticky vs non-sticky start behavior."
date: 2026-07-22T09:00:00.000Z
cascade:
  showReadingTime: true
tags:
- Infosec
- Android Security
- Mobile Pentesting
- Services
- IPC
---

## Pentesting Android Services

Services are the Android component that runs long-lived work in the background. Think of an app that keeps uploading large files, plays audio while the UI is closed, or syncs data on a schedule. Like every other component, a Service has to be declared in `AndroidManifest.xml` under the `<service>` tag, and even when it is exported it can be locked down further with `android:permission`.

**Why does this matter?** Because a Service is often the piece of the app that actually *does* the privileged work: talking to internal APIs, touching files, or moving data between processes. If another app can reach that Service from outside the sandbox, it can effectively borrow the victim app's privileges to run those internal actions.

> The easiest way to think about it is this: an Activity is what the user sees, a Service is what the app runs on its behalf. When a Service is exported without proper checks, an attacker can walk up to that engine room and press buttons directly.

**Job Service.** A very common exported Service you will see in the wild is an Android Job Scheduler service. It looks juicy at first, but it is guarded by `android.permission.BIND_JOB_SERVICE`, which only the system can hold. That means you cannot directly bind to it from a normal app, and it can usually be ignored when hunting for bugs.

## Bound vs Unbound Services

There are two flavors of Services worth separating in your head:

* **Unbound Services**: started to run something in the background and then stopped. The entry point is `onStartCommand()`, and it takes an `Intent` from the caller. That `Intent` is attacker-controlled, so *this is the main attack surface for started Services*.
* **Bound Services**: another app calls `bindService()` and the two sides keep talking through an `IBinder` interface. This is closer to a live RPC channel than a fire-and-forget task.

After you identify an exposed Service in the manifest, the next thing to check is the `onBind()` method. That method tells you whether the Service is meant to be bound to at all, and if so, what interface it hands back.

**Non-bindable Services** behave a lot like broadcast receivers. They run in the background, `onBind()` is not really used as an interaction point, and the attack focus goes back to whatever intent the Service accepts on start.

> **What about LocalBinders?** If `onBind()` returns `null` or throws, the Service simply cannot be bound to from outside. `LocalBinder` implementations are only meant to be used inside the same app process, so from an attacker's perspective they are effectively unbindable.

## Message Handler Services

In Android, a `Messenger` is a common way to implement Inter-Process Communication (IPC). It lets an app send `Message` objects into a background `Service`, and the Service reacts to them. *Where the weakness lies:* if the Service is exported and does not validate who is talking to it, any installed app can send it those messages and trigger internal actions remotely.

**Reversing the handler.** When auditing an app, check `AndroidManifest.xml` for exported services. If you find one, look for its `Handler` implementation, usually an inner class called something like `IncomingHandler`. This "message handler" pattern is the typical shape of a Service built on top of the [`Messenger`](https://developer.android.com/reference/android/os/Messenger) class.

A `Messenger` service is easy to recognize: its `onBind()` returns an `IBinder` produced by a `Messenger` instance.

```java
public class MyMessageService extends Service {
    public static final int MSG_SUCCESS = 42;
    final Messenger messenger = new Messenger(new IncomingHandler(Looper.getMainLooper()));

    @Override // android.app.Service
    public IBinder onBind(Intent intent) {
        return this.messenger.getBinder();
    }

    class IncomingHandler extends Handler {

        IncomingHandler(Looper looper) {
            super(looper);
        }

        @Override // android.os.Handler
        public void handleMessage(Message message) {
            if (message.what == 42) {
                // ...
            } else {
                super.handleMessage(message);
            }
        }
    }
}
```

The inline class extending [`Handler`](https://developer.android.com/reference/android/os/Handler) contains a `handleMessage()` method that implements the actual service logic. The attacker fully controls the `Message` coming in, including its `what` field, `arg1`, `arg2`, and any `Bundle` payload. To interact with this Service, a malicious app needs to bind to it and send the "magic" number `42` in order to trigger the success branch.

* **Where**: exported Service with a `Messenger`-backed `onBind()` and an `IncomingHandler`.
* **The Move**: bind to the Service from a PoC app, build a `Message` with `Message.obtain(null, 42)`, and send it through the `Messenger`.
* **The Vulnerability**: the Service trusts any caller that can reach it, so the "magic number" acts as the only gate and there is no real authorization check.

You can practice interacting with a basic message service using the Intent Attack Surface app.

## Sticky vs Non-Sticky Services

Once you understand the start flow, the next thing that trips people up is what happens after `onStartCommand()` returns. The return value tells Android how to behave if the Service gets killed under memory pressure, and that behavior has security implications for how attacker-controlled input is replayed.

* **`START_NOT_STICKY`**: if the system kills the Service, it will not recreate it automatically. The original `Intent` is dropped. Safer default for one-shot work.
* **`START_STICKY`**: the system will recreate the Service after it is killed, but it will call `onStartCommand()` with a `null` intent. The Service is expected to know what to do on its own.
* **`START_REDELIVER_INTENT`**: the system recreates the Service *and* redelivers the last `Intent` that was passed in. Useful for jobs that must complete, like uploads.

> From a security perspective, `START_REDELIVER_INTENT` is the interesting one. An attacker-controlled `Intent` can be replayed by the system itself after the Service is killed and restarted. If the Service does not re-validate the caller or the payload on redelivery, you effectively get a second bite at the same attack.

## Summary

Android Services are the background workers of an app, and like every other Android component, their attack surface is decided in the manifest first and in the code second. **Exported** plus **no meaningful permission** is the combination that turns a Service into an outside-reachable entry point, and from there `onStartCommand()` and `onBind()` become the two doors an attacker knocks on.

For started Services, the attacker controls the `Intent`, and sticky start modes can even cause that `Intent` to be replayed by the system. For bound Services, especially the ones built on `Messenger`, the attacker controls the `Message` objects flowing into `handleMessage()`, and the whole thing collapses to a single question: *does the Service actually check who is talking to it, or does it trust every caller that made it past the manifest?* When the answer is "it trusts everyone", any installed app on the device can trigger internal actions it was never supposed to reach.
