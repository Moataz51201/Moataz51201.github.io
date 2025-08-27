---
layout: post
title: "Android Architecture: Exploring the android OS"
date: 2025-08-26
categories: [Android,Android Apps,Operating Systems,Mobile Development]
image: https://cdn-images-1.medium.com/max/800/1*W46NKwMaFd0CG8S3Ur29BA.jpeg
---

**1.** **Linux Kernel**

![](https://cdn-images-1.medium.com/max/800/1*9vQ9pJOzb1jqEuEvYnvDcg.jpeg)

The **Linux Kernel** is the foundation of the Android operating system and plays a critical role in managing hardware resources and ensuring smooth interactions between hardware and software layers. Here’s a detailed breakdown of the Linux Kernel’s significance and its key components in the context of Android:

**. Role of the Linux Kernel in Android**

**Hardware Abstraction**: Acts as a bridge between hardware (e.g., CPU, memory, peripherals) and software (e.g., Android Framework).

- **Device Drivers**: Provides drivers for all hardware components, such as:
- **Display Drivers**: For rendering UI and managing screens.
- **Input Drivers**: For handling touch, keyboard, and mouse inputs.
- **Wi-Fi and Networking Drivers**: For internet and communication.
- **Camera Drivers**: For capturing photos and videos.
- **Audio Drivers**: For playing sounds and managing audio input/output.

**Process and Resource Management**:

- **CPU Scheduling**: Ensures efficient use of CPU resources among various apps and background services.
- **Memory Management**: Allocates and manages memory for running applications.
- **Power Management**: Optimizes battery usage by controlling processes and hardware operations.

**Security**:

- Provides isolation between processes.
- Implements **SELinux (Security-Enhanced Linux)** for mandatory access control (MAC).
- Enforces permissions at the kernel level.

**. Features Specific to Android’s Linux Kernel:**

**Android-specific Enhancements**:

- **WakeLocks**: Prevents the device from going to sleep during critical operations like downloading files or playing music.
- **Ashmem (Anonymous Shared Memory)**: Optimizes memory usage by enabling memory sharing between processes.
- **Binder IPC**: Android’s unique IPC mechanism that enables communication between apps and system services.
- **Low Memory Killer (LMK)**: A memory management feature specific to Android that terminates background processes when RAM is low.

**Power Efficiency**: Android kernel implements advanced power-saving mechanisms like Doze mode and App Standby.

**Security Features**:

- **SELinux**: Ensures strict access control.
- **Verified Boot**: Verifies the integrity of the kernel and system partition during startup.
- **dm-verity**: Detects any changes or corruption in system files.

**Android Kernel Customization:** While Android is built on the Linux Kernel, Google customizes it to meet the specific needs of Android devices:

- **Version**: Android doesn’t always use the latest Linux kernel version; instead, Google integrates and modifies stable versions to suit Android’s requirements.
- **OEM Kernels**: Device manufacturers (like Samsung, Xiaomi) further customize the kernel to optimize their hardware.

**. Kernel Security in Android**

**Kernel Hardening**:

- Android employs techniques like Address Space Layout Randomization (ASLR) to prevent kernel-level exploits.
- Enforces the use of **memory protections** (e.g., read-only memory for critical sections).

**Regular Updates**: Android kernels receive security patches from Google to mitigate vulnerabilities.

* * *

**2.** **Hardware Abstraction Layer (HAL)**

![](https://cdn-images-1.medium.com/max/800/1*mNRIiKmIDCcz7Rpn88Y9PQ.jpeg)

L2: **Hardware Abstraction Layer (HAL)** is a critical part of the Android architecture, sitting between the **Linux Kernel** and the **Android Framework**. It provides a standardized interface for the Android operating system to interact with hardware components. This design ensures that the Android Framework can remain hardware-agnostic, allowing Android to run on a wide variety of devices without needing to modify the higher-level code.

**What is the Hardware Abstraction Layer (HAL)?**

- The HAL is a collection of software libraries or modules that provide a bridge between the hardware-specific code (kernel drivers) and the Android Framework APIs.
- It abstracts the hardware details and provides a consistent interface for the framework, so app developers and system developers don’t need to handle hardware differences directly.

**Role of HAL in Android**

- **Hardware Independence**:
- HAL standardizes access to hardware, enabling the Android operating system to run on devices with different hardware architectures (e.g., ARM, x86).
- **Modular Design**:
- HAL is split into separate modules, with each module dedicated to a specific hardware component (e.g., audio, camera, sensors).
- **Driver Interaction**:
- HAL interacts with the hardware drivers in the Linux Kernel and translates framework requests into hardware-level commands.

**Device Compatibility**: HAL allows manufacturers to provide their own implementation for accessing hardware while ensuring compliance with Android’s framework.

**Components of HAL**

HAL consists of multiple modules, each corresponding to a specific hardware component. Some common HAL modules include:

1. **Audio HAL**:

<!--THE END-->

- Handles audio playback and recording.
- Provides functions to control volume, manage audio streams, and interact with audio hardware.

**2. Camera HAL**:

- Manages camera devices and features.
- Provides functions for capturing photos, recording videos, and accessing camera parameters.

**3. Sensor HAL**:

- Interfaces with accelerometers, gyroscopes, magnetometers, and other sensors.
- Provides data to apps and the system, such as motion tracking or orientation.

**4. Bluetooth HAL**:

- Enables communication with Bluetooth devices.
- Manages pairing, data transfer, and audio streaming over Bluetooth.

**5. Wi-Fi HAL**:

- Handles Wi-Fi connectivity and management.
- Provides features like scanning for networks, connecting to access points, and managing data transfer.

**6. Graphics HAL**:

- Responsible for rendering graphics using hardware acceleration.
- Often implemented using APIs like OpenGL or Vulkan.

**7. Power HAL**:

- Manages power-saving features and device power states.
- Provides APIs to control CPU frequency scaling, screen brightness, and sleep modes.

**8. Vibrator HAL**:

- Controls the device’s vibration motor.
- Used for feedback like haptic responses in games and notifications.

**How HAL Works**

**Integration with Android Framework**:

- The Android Framework APIs (used by applications) communicate with HAL modules.

EX:

- When an app requests the camera, the Android Framework sends the request to the Camera HAL.
- The Camera HAL interacts with the Linux Kernel drivers to access the hardware.

**Hardware Interface Definition Language (HIDL)**:

- From Android 8.0 (Oreo) onward, HAL implementations use HIDL to define the interface between the framework and HAL modules.
- HIDL ensures type safety, versioning, and backward compatibility.
- Before HIDL, HAL modules used a shared library model with .so files.

**Vendor Interface**:

- HAL modules form part of the vendor implementation, which is specific to the device manufacturer.
- This separation allows Google to update the Android Framework independently of vendor-specific changes

**. Practical Examples**

1. **Audio Playback**:

<!--THE END-->

- App → Android Media Framework → Audio HAL → Audio Driver → Speaker.

**2. Taking a Photo**:

- App → Camera API → Camera HAL → Camera Driver → Camera Hardware.

* * *

**3. Android Runtime (ART)**

![](https://cdn-images-1.medium.com/max/800/1*9krcXxUGo0A-6Gtzos0EtA.jpeg)

The **L3 layer in Android**, which includes **Native Libraries** and the **Android Runtime (ART)**, plays a crucial role in executing Android applications and providing core system functionalities. Here’s an in-depth breakdown:

### Native Libraries (L3)

**Native Libraries** in Android are written in C or C++ and provide functionality that is directly leveraged by the **Android Framework APIs** or the **Android Runtime**. These libraries are optimized for performance and offer critical services for app development and device operations.

### Key Features

- Provide low-level system capabilities to the higher layers.
- Optimize performance by using C/C++ for resource-intensive tasks.
- Enable applications to perform advanced tasks such as graphics rendering, database management, and media playback.

### Common Native Libraries

**libc:** Provides standard C library functions like memory allocation, file I/O, and string manipulation.

**OpenGL ES:** Enables hardware-accelerated graphics rendering for 2D and 3D graphics.

**WebKit:** Powers the web browser and WebView components for displaying web pages.

**SQLite:** Offers a lightweight, relational database engine for storing app data locally.

**SSL/TLS (BoringSSL):** Handles secure communications using cryptographic protocols.

**Media Framework:** Supports playback and recording of audio and video, including codecs.

**Zlib:** Provides compression and decompression of data.

**OpenSSL:** Used for cryptographic functions and secure communication.

### Android Runtime (ART)

The **Android Runtime (ART)** is the environment where Android applications are executed. Introduced in **Android 4.4 (KitKat)** as a replacement for the **Dalvik Virtual Machine (DVM)**, ART brought significant improvements in performance, memory management, and debugging capabilities.

### Key Features of ART

1\. **Ahead-of-Time (AOT) Compilation**:

- ART compiles applications during installation into machine code (native instructions).
- This eliminates the need for Just-in-Time (JIT) compilation during runtime, reducing the overhead.

2\. **Better Performance**:

- Faster app startup times compared to Dalvik.
- Reduced CPU and memory usage.

3\. **Garbage Collection (GC)**:

- ART improves memory management with more efficient garbage collection mechanisms.
- The garbage collector minimizes application pauses by performing concurrent GC cycles.

4\. **Enhanced Debugging**: ART offers advanced debugging tools like detailed diagnostic information and better crash analysis.

5\. **Compatibility**: ART supports the same Java bytecode as Dalvik, ensuring backward compatibility with older apps.

6\. **Profiling**: ART enables developers to optimize app performance by providing runtime profiling information.

**How ART Works**

1\. **Compilation**:

- When an app is installed, ART compiles its **DEX (Dalvik Executable)** files into native machine code using the **AOT compiler**.
- The compiled code is stored in the device’s storage for quick execution.

2\. **Execution**: During runtime, ART runs the precompiled machine code, ensuring faster performance and lower power consumption.

3\. **Garbage Collection**: ART uses an optimized GC mechanism to reclaim unused memory, ensuring efficient memory utilization.

### Key Differences Between ART and Dalvik

- **Compilation**

**Dalvik (DVM):** Just-in-Time (JIT) at runtime

**Android Runtime (ART):** Ahead-of-Time (AOT) during app installation

- **Performance**

**Dalvik (DVM):** Slower app startup and higher runtime overhead

**Android Runtime (ART):** Faster app startup and better performance

- **Memory Usage**

**Dalvik (DVM):** Higher runtime memory usage

**Android Runtime (ART):** Optimized memory management

- **Battery Efficiency**

**Dalvik (DVM):** Less efficient

**Android Runtime (ART):** More power-efficient

- **Debugging Tools**

**Dalvik (DVM):** Basic debugging support

**Android Runtime (ART):** Advanced debugging and profiling tools

### Native Libraries and ART in Action

When an app runs on Android:

1. **ART** executes the app using the precompiled machine code.
2. If the app requests certain functionalities, the **Android Framework** interacts with the **Native Libraries** through HAL (Hardware Abstraction Layer) or directly with ART.

<!--THE END-->

- Example:
- A media player app uses **Media Framework** to play videos.
- A database app uses **SQLite** for data storage.

* * *

**5. Android Framework**

![](https://cdn-images-1.medium.com/max/800/1*2G-4sPpbB4axoy8FhwPDkw.jpeg)

The **L4: Android Framework** layer is a core part of the Android operating system, acting as a bridge between the system’s underlying layers and application-level development. It provides a structured set of APIs and services that developers use to create Android apps. The Android Framework abstracts the complexities of hardware interaction and system processes, allowing developers to focus on building feature-rich applications.

### Key Features of the Android Framework

1\. **Simplified API Access**: Developers can interact with the device’s underlying hardware and system services using high-level APIs, without needing to deal with low-level implementations.

2\. **Modular Components**: The framework is designed around reusable components like activities, services, and broadcast receivers, which simplify application development.

3\. **Core System Services**: Provides essential services such as window management, activity lifecycle management, resource handling, and notifications.

4\. **Security and Permissions**: Manages application sandboxing and permissions to ensure apps run securely without interfering with one another.

### Core Components of the Android Framework

The Android Framework is organized into several key components and services:

### 1. Application Components

These are building blocks that developers use to create apps:

· **Activities**:

- Represent a single screen of the user interface (UI).
- Example: A login screen or a settings page.

· **Services**:

- Run in the background to perform long-running tasks without a UI.
- Example: Music playback or data synchronization.

· **Broadcast Receivers**:

- Handle messages broadcast by the system or other applications.
- Example: Reacting to changes like battery low or network availability.

· **Content Providers**:

- Allow apps to share and access structured data (e.g., from a database or file system).
- Example: Contacts or media storage.

### 2. Managers and System Services

The Android Framework includes numerous managers that provide access to system-level functionality. Some of the most important ones are:

**ActivityManager:** Manages the lifecycle of applications and activities.

**WindowManager:** Handles the display and placement of UI components.

**NotificationManager:** Allows apps to send and manage system notifications.

**ContentResolver:** Facilitates access to content providers and shared data.

**LocationManager:** Provides access to location services using GPS, Wi-Fi, or cellular networks.

**PackageManager:** Manages app installation, removal, and access to app metadata.

**SensorManager:** Provides access to hardware sensors (e.g., accelerometer, gyroscope).

**ConnectivityManager:** Handles network connectivity (Wi-Fi, mobile data, VPN, etc.).

**AudioManager:** Manages audio output, volume controls, and ringer modes.

**TelephonyManager:** Provides access to telephony features like SIM card information and call state.

**CameraManager:** Interfaces with the camera hardware for capturing photos and videos.

### 3. UI Framework

The Android Framework provides extensive support for designing and managing user interfaces:

· **View System**:

- Contains pre-built UI components like buttons, text views, and scroll views.
- Example: `Button`**,** `TextView`**,** `RecyclerView`**.**

· **Layouts**:

- Help organize UI components in a structured manner.
- Example: `LinearLayout`**,** `ConstraintLayout`**,** `RelativeLayout`**.**

· **Resource Management**:

- Manages resources like images, strings, and layouts stored in the `res` directory.
- Example: `R.string.app_name` or `R.drawable.icon`.

· **Themes and Styles**:

- Allows for customization of the app’s look and feel.

### 4. Resource Access and Management

The framework simplifies access to resources, which include:

- **Drawable Resources**: Images or graphic content.
- **String Resources**: Text or localized content.
- **Animation Resources**: Define animations and transitions.
- **Layouts**: XML files that define the app’s UI structure.
- **Raw Resources**: Arbitrary files stored in the `res/raw` directory.

### 5. Multitasking and App Lifecycle

The Android Framework handles multitasking and the lifecycle of apps through **ActivityManager** and **ServiceManager**. Developers must manage app states (e.g., foreground, background) using lifecycle methods like:

- `onCreate()`
- `onStart()`
- `onResume()`
- `onPause()`
- `onStop()`
- `onDestroy()`

### 6. Permissions and Security

The Android Framework enforces a strict permission model:

- Apps must explicitly request permissions for sensitive operations (e.g., accessing the camera or location).
- Permissions are declared in the `AndroidManifest.xml` file.
- Runtime permissions are introduced (from Android 6.0) for greater user control.

### 7. Inter-App Communication

The framework uses **Intents** for communication:

- **Explicit Intents**: Target specific app components.
- **Implicit Intents**: Let the system decide which app should handle the request (e.g., opening a web link).

### How the Android Framework Fits into the Architecture

- The Android Framework sits above the **Native Libraries/ART** and below the **Applications layer**.
- It provides **app developers** with the tools and services to interact seamlessly with the **device’s hardware** and **system functionalities**.
- It relies on **Native Libraries** for low-level tasks (e.g., graphics, database) and **Android Runtime (ART)** for executing app code.

* * *

**6. Applications**

![](https://cdn-images-1.medium.com/max/800/1*R_AnjVE82CfON9KWJvzaiQ.jpeg)

The **L5: Applications** layer in the Android architecture is the topmost layer, representing the user-facing side of the operating system. This layer contains all the apps that users interact with on their devices, including both pre-installed (system) apps and third-party apps downloaded from the Google Play Store or other sources.

### Key Features of the Applications Layer

1\. **User-Facing Interface**:

- This is where users directly interact with the system through graphical user interfaces (GUIs).
- Applications provide a range of functionalities, such as messaging, browsing, gaming, or managing device settings.

2\. **Built on Android Framework**:

- All apps rely on APIs and services provided by the **Android Framework** (L4).
- Apps interact with system components like cameras, location services, and sensors through these APIs.

3\. **Diverse Application Types**:

- Pre-installed system apps, such as the Phone, Messages, Settings, and Camera apps.
- Third-party apps installed from app stores or sideloaded APK files.

4\. **Sandboxing and Security**: Each application runs in its own isolated environment (sandbox), ensuring data protection and preventing unauthorized access to other apps or system files.

5\. **Customizability**: Users can customize their devices by installing apps that suit their needs, such as alternative web browsers, keyboards, or launchers.

### Types of Applications in L5

### 1. System Applications (Pre-installed)

These are apps bundled with the Android OS by the device manufacturer or Google:

- **Phone**: Manage calls and contacts.
- **Messages**: Handle SMS and MMS.
- **Settings**: Configure device preferences (Wi-Fi, Bluetooth, sound, etc.).
- **Camera**: Capture photos and videos using device hardware.
- **Clock, Calendar, Calculator**: Core utilities.

**Role**:  
These apps ensure basic functionality and are integral to the Android ecosystem.

### 2. User Applications (Third-Party Apps)

These are apps that users install from sources like:

- **Google Play Store**: The official app marketplace for Android.
- **Alternative Stores**: Amazon Appstore, F-Droid, etc.
- **Sideloading**: Installing APKs from external sources.

**Examples**:

- Social Media: Instagram, Twitter, Facebook.
- Productivity: Microsoft Office, Google Drive.
- Entertainment: Netflix, YouTube, Spotify.
- Games: PUBG, Candy Crush, Genshin Impact.

**Role**:  
These apps extend the device’s capabilities, catering to a wide range of user needs.

### How Applications Interact with the System

1\. **API Usage**: Applications use APIs provided by the **Android Framework** to interact with device hardware and software features (e.g., GPS, camera, storage).

2\. **Intents for Communication**: Apps communicate using **Intents**, which can launch activities, services, or broadcast events.

3\. **Permissions**:

- Apps must request permissions for sensitive operations, like accessing the camera or location.
- Permissions ensure user privacy and security.

4\. **Updates**: Apps can be updated via the Play Store to fix bugs, introduce new features, or address security vulnerabilities.

### Application Distribution

1\. **Google Play Store**:

- The official Android app store managed by Google.
- Apps are vetted for compliance with Play Store policies.

2\. **APK Files**:

- Users can manually install apps by downloading APKs from other sources (sideloading).
- Requires enabling “Install unknown apps” in the device settings.

3\. **OEM Stores**: Some manufacturers, like Samsung, provide their own app stores.

### How Applications Fit into the Android Architecture

- Applications are built **on top of the Android Framework**, utilizing its tools and APIs to provide functionality.
- They interact indirectly with the **Native Libraries** and **Linux Kernel** through the framework, ensuring abstraction and ease of development.
- They are isolated from each other and the system core via the Android **sandboxing model**, which enhances security.

### Examples of Android Application Use Cases

1\. **Communication**: Messaging apps like WhatsApp, Telegram, or Signal for chat and calls.

2\. **Productivity**: Google Docs, Evernote, or Microsoft Teams for work-related tasks.

3\. **Entertainment**: Streaming platforms like Netflix or Hulu for movies and shows.

4\. **Health and Fitness**: Apps like Fitbit or Google Fit to monitor activity and health metrics.

By [Moataz Osama](https://medium.com/@mezo512) on [February 7, 2025](https://medium.com/p/55ea161fe7aa).

[Canonical link](https://medium.com/@mezo512/android-architecture-exploring-the-android-os-55ea161fe7aa)

Exported from [Medium](https://medium.com) on August 26, 2025.