---
layout: post
title: "Android Hacking Series Part 1: Understanding APK Structure and Smali Code"
date: 2025-08-26
categories: [Android Pentesting,Android Apps,Operating Systems,Mobile Development]
image: https://cdn-images-1.medium.com/max/800/1*-un8BoQeHXigDDD3LVR9eg.jpeg
---

### Introduction

Android dominates the mobile OS market, making it a prime target for attackers and security researchers alike. Its open-source nature, extensive app ecosystem, and varying levels of device security create numerous attack surfaces, ranging from **insecure data storage** to **improper access control** and **privilege escalation exploits**.

This **Android Hacking Series** is designed for penetration testers, cybersecurity enthusiasts, and developers who want to understand how Android applications and devices can be exploited—and, more importantly, how to **defend against such attacks**.

### Before You Begin: Prerequisites

Before diving into Android exploitation, it’s crucial to have a strong foundation in the following topics:

✅ **Android Architecture: Understanding** the Android OS stack, including the Linux kernel, native libraries, Android runtime (ART), and framework. *(Read my article on* [*Android Architecture*](https://medium.com/@mezo512/android-architecture-exploring-the-android-os-55ea161fe7aa)*.)*

✅ **Android Components: A** deep dive into the four core Android components: activities, services, broadcast receivers, and content providers. *(Check out my article on* [*Android components*](https://medium.com/@mezo512/android-components-core-building-blocks-of-android-apps-5e4358811107)*.)*

These fundamentals are essential for understanding how Android applications work under the hood and how attackers exploit vulnerabilities within them. If you haven’t read my previous articles, I highly recommend reviewing them before proceeding.

#### Native And Hybrid Applications

**Native**: They are those developed applications only and exclusively for mobile operating systems, either **Android** or **IOS**. In Android you use the Java or kotlin programming language, while in IOS you make use of Swift or Objective-C. These programming languages are the official ones for the respective operating systems.

**Hybrid**: These applications use technologies such as HTML, CSS and JavaScript, all of these linked and processed through frameworks such as Apache Córdova “PhoneGap”, Ionic, among others.

#### What is android’s SMALI code?

When you create an application code, the apk file contains a .dex file, which contains binary Dalvik bytecode. Smali is an assembly language that runs on Dalvik VM, which is Android’s JVM.

Example:

![](https://cdn-images-1.medium.com/max/800/1*uEAOS8MJ1p24RWH8aKYluw.png)

![](https://cdn-images-1.medium.com/max/800/1*zuvQH52MM770cfhf73UUYg.png)

**Smali Syntax — Types**

![](https://cdn-images-1.medium.com/max/800/1*d3WBxYFVVr7cQ042bNszeA.png)

* * *

**Smali Registers by JesusFreke**

**Introduction**

In dalvik’s bytecode, registers are always **32** bits, and can hold any type of value. 2 registers are used to hold 64 bit types (Long and Double).

**Specifying the number of registers in a method**

There are two ways to specify how many registers are available in a method. the .registers directive specifies the **total** number of registers in the method, while the alternate .locals directive specifies the number of **non-parameter** registers in the method. The total number of registers would therefore include the registers needed to hold the method parameters.

**How method parameters are passed into a method**

When a method is invoked, the parameters to the method are placed into the last n registers. If a method has 2 arguments, and 5 registers (v0-v4), the arguments would be placed into the last 2 registers — v3 and v4.

The first parameter to a non-static methods is always the object that the method is being invoked on.

For example, let’s say you are writing a non-static method **LMyObject;-&gt;callMe(II)V**. This method has 2 integer parameters, but it also has an implicit **LMyObject;** parameter before both integer parameters, so there are a total of **3** arguments to the method.

Let’s say you specify that there are 5 registers in the method **(v0-v4)**, with either the **.registers** 5 directive or the **.locals** 2 directive (i.e. 2 ***local* registers + 3 parameter registers**). When the method is invoked, the object that the **method** is being invoked on (i.e. the this reference) will be in **v2**, the first integer parameter will be in **v3**, and the **second** integer parameter will be in **v4**.

For static methods it’s the same thing, except there isn’t an implicit **this** argument.

**Register names**

There are two naming schemes for registers — the **normal *v*** naming scheme and the *p* naming scheme for parameter registers. The first register in the *p* naming scheme is the first parameter register in the method. So let’s go back to the previous example of a method with 3 arguments and 5 total registers. The following table shows the **normal *v* name** for each register, followed by the ***p* name** for the **parameter** registers

v0 the first local register

v1: the second local register

v2 — p0 — the first parameter register

v3- p1 — the second parameter register

v4 — p2 — the third parameter register

You can reference parameter registers by either name — it makes no difference.

**Motivation for introducing parameter registers**

The *p* naming scheme was introduced as a practical matter, to solve a common annoyance when editing smali code.

Say you have an existing method with a number of parameters and you are adding some code to the method, and you discover that you need an extra register. You think “No big deal, I’ll just increase the number of registers specified in the .registers directive!”.

Unfortunately, it isn’t quite that easy. Keep in mind that the method parameters are stored in the **last** registers in the method. If you increase the number of registers — you change which registers the method arguments get put into. So you would have to change the .registers directive **and** renumber every parameter register.

But if the *p* naming scheme was used to reference parameter registers throughout the method, you can easily change the number of registers in the method, without having to worry about renumbering any existing registers.

Note: by default baksmali will use the *p* naming scheme for parameter registers. If you want to disable this for some reason and force baksmali to always use the *v* naming scheme, you can use the -p/ — no-parameter-registers option.

**Long/Double values**

As mentioned previously, long and double primitives (J and D respectively) are 64 bit values, and require 2 registers. This is important to keep in mind when you are referencing method arguments. For example, let’s say you have a (non-static) method **LMyObject;-&gt;MyMethod(IJZ)V.** The parameters to the method are LMyObject;, int, long, bool. So this method would require 5 registers for all of its parameters.

**Register Type**

p0 this

p1 I

p2, p3 J

p4 Z

Also, when you are invoking the method later on, you do have to specify both registers for any double-wide arguments in the register list for the invoke-**instruction.**

* * *

#### Application Structure. (APK)

![](https://cdn-images-1.medium.com/max/800/1*cfOuFhMJLMw648F75kI2tw.png)

**AndroidManifest.xml**: the manifest file in binary XML format.

**classes.dex:** application code compiled in the dex format.

**resources.arsc:** file containing precompiled application resources, in binary XML.

**res/:** folder containing resources not compiled into resources.arsc

**assets/:** optional folder containing applications assets, which can be retrieved by AssetManager.

**lib/:** optional folder containing compiled code — i.e. native code libraries.

**META-INF/:** folder containing the MANIFEST.MF file, which stores meta data about the contents of the JAR. which sometimes will be store in a folder named original.The signature of the APK is also stored in this folder.

Every APK file includes an AndroidManifest.xml file which declares the application’s package name, version components and other metadata. Full detail of Android manifest specs file can be view here. Below is just some common attributes that can identify in AndroidManifest.

**Manifest tag** : contains android installation mode, package name, build versions

**Permissions** : custom permission and protection level

**uses-permissions** : requests a permission that must be granted in order for it to operate, full list of permission api can refer [here](https://developer.android.com/reference/android/Manifest.permission.html).

**uses-feature** : Declares a single hardware or software feature that is used by the application.

**Application** : The declaration of the application. Will contains all the activity

**Activity** : Declares an activity that implements part of the application visual user interface.

**intent-filter** : Specifies the types of intents that an activity, service, or broadcast receiver can respond to.

**Service**: Declare a service as one of the application components.

**Receiver**: Broadcast receivers enable applications to receive intents that are broadcast by the system or by other applications, even when other components of the application are not running.

**Provider**: Declares a content provider component. A content provider is a subclass of ContentProvider that supplies structured access to data managed by the application.

* * *

### Important directories

The directories listed below are the most important directories in an Android device and are worth being aware of.

- **/data/data:** Contains all the applications that are installed by the user.
- **/data/user/0:** Contains data that only the app can access.
- **/data/app:** Contains the APKs of the applications that are installed by the user.
- **/system/app:** Contains the pre-installed applications of the device.
- **/system/bin:** Contains binary files.
- **/data/local/tmp:** A world-writable directory.
- **/data/system:** Contains system configuration files.
- **/etc/apns-conf.xml:** Contains the default Access Point Name (APN) configurations. APN is used in order for the device to connect with our current carrier’s network.
- **/data/misc/wifi:** Contains WiFi configuration files.
- **/data/misc/user/0/cacerts-added:** User certificate store. It contains certificates added by the user.
- **/etc/security/cacerts/:** System certificate store. Permission to non-root users is not permitted.
- **/sdcard:** Contains a symbolic link to the directories DCIM, Downloads, Music, Pictures, etc.

* * *

**Emulators**: An Android emulator is an Android Virtual Device, that represents a specific Android device. You can use an Android emulator as a target platform to run and test your Android applications on your PC.

Don’t necesary Install emulator if have a rooted phone. My favorite emulator for windows, linux and Mac is Genymotion as it is very easy to use. Create account and download the installer for your platform/Operating system.

[Genymotion Android Emulator](https://www.genymotion.com/)

Enable Developer options in your emulator or rooted phone is necessary active this function for use debug usb.

You can unlock the Developer options on any Android smartphone or tablet by locating the Build number in your Settings menu and tapping it multiple times. However, the exact location of the aforementioned build number may differ depending on your phone’s manufacturer.

**Settings &gt; About Phone &gt; Build number &gt; Tap it 7 times to become developer;**

**Now, Settings &gt; Developer Options &gt; USB Debugging.**

* * *

Methodology

![](https://cdn-images-1.medium.com/max/800/1*OjJDrZXqHcmtg8QBgtemzg.png)

Information collection is the first thing we need to do, as this information will guide us to the next stage in our penetration tests.

**Black Box**: In penetration testing, black-box testing refers to a method where an ethical hacker has no knowledge of the system being attacked.

How do I find the application of the organization?

![](https://cdn-images-1.medium.com/max/800/1*_uCX0AQpubQ43glBD6bZOw.png)

Easy, **play store**: is a digital distribution platform for mobile apps for devices with Android operating system.

**White Box**: White box penetration testing can also be called glass box penetration testing or clear box penetration testing. In any case, it’s an approach to penetration testing that relies on the knowledge of the target system’s internal configuration. It uses this information for the test cases.

In a real scenario the client it will give us the mobile app, users and passwords to perform the login and also a user manual of how the application works.

* * *

We will describe how to create a static analysis of the application in the upcoming article. Stay Tuned

By [Moataz Osama](https://medium.com/@mezo512) on [February 16, 2025](https://medium.com/p/b4de42db3589).

[Canonical link](https://medium.com/@mezo512/android-hacking-series-b4de42db3589)

Exported from [Medium](https://medium.com) on August 26, 2025.