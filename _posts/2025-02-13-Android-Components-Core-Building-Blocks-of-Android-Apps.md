---
layout: post
title: "Android Components: Core Building Blocks of Android Apps"
date: 2025-08-26
categories: [Android,Android Apps,Operating Systems,Mobile Development]
image: https://cdn-images-1.medium.com/max/800/1*cGbufr7PUhWiCSd_hMAsug.png
---

Android applications are built using four main **Android components**, each serving a specific role in the app’s functionality. These components are managed by the Android system and interact with each other using **intents** and **permissions**.

#### **Activity**

An **Activity** is a single, focused task that the user can interact with. Think of it as a “screen” in an app. For example, in a messaging app:

- **Main Activity**: Shows your contact list.
- **Detail Activity**: Displays the chat screen for a selected contact.

**. Activity Lifecycle — The Core Concept**

One of the most critical aspects of understanding activities is their **lifecycle**. Android manages activities using a series of callback methods. Here’s a diagram to visualize it:

![](https://cdn-images-1.medium.com/max/800/1*aL1Wm-K_EebgTtHyGaSN0A.png)

Each state has specific purposes:

**onCreate**: Called when the activity is first created. This is where you should do all of your normal static set up: create views, bind data to lists, etc. This method also provides you with a Bundle containing the activity’s previously frozen state, if there was one. Always followed by **onStart().**

**onStart**: Called when the activity is becoming visible to the user. Followed by **onResume**() if the activity comes to the foreground, or **onStop()** if it becomes hidden..

**onResume**: Makes the activity interactive. Called when the activity will start interacting with the user. At this point your activity is at the top of its activity stack, with user input going to it. Always followed by **onPause**().

**onPause**: Freezes updates (e.g., stop animations). Called when the activity loses foreground state, is no longer focusable or before transition to stopped/hidden or destroyed state. The activity is still visible to user, so it’s recommended to keep it visually active and continue updating the UI. Implementations of this method must be very quick because the next activity will not be resumed until this method returns. Followed by either **onResume**() if the activity returns back to the front, or **onStop**() if it becomes invisible to the user.

**onStop**: Hides the activity. Called when the activity is no longer visible to the user. This may happen either because a new activity is being started on top, an existing one is being brought in front of this one, or this one is being destroyed. This is typically used to stop animations and refreshing the UI, etc. Followed by either **onRestart**() if this activity is coming back to interact with the user, or **onDestroy**() if this activity is going away.

**onDestroy**: Cleans up resources. The final call you receive before your activity is destroyed. This can happen either because the activity is finishing (someone called `Activity.finish` on it), or because the system is temporarily destroying this instance of the activity to save space. You can distinguish between these two scenarios with the `isFinishing()` method.

**Example: Handling the Lifecycle**

> **public class MainActivity extends AppCompatActivity {**

> **@Override**

> **protected void onCreate(Bundle savedInstanceState) {**

> **super.onCreate(savedInstanceState);**

> **setContentView(R.layout.activity\_main);**

> **Log.d(“ActivityLifecycle”, “onCreate called”);**

> **}**

> **@Override**

> **protected void onPause() {**

> **super.onPause();**

> **Log.d(“ActivityLifecycle”, “onPause called”);**

> **}**

> **}**

**. Starting an Activity**

To launch an activity, Android uses **Intents**.

**Explicit Intent Example:**

Start **DetailActivity** directly:

> **Intent intent = new Intent(MainActivity.this, DetailActivity.class);**

> **intent.putExtra(“userID”, 123);**

> **startActivity(intent);**

**Implicit Intent Example:**

Open a web page in the browser:

> **Intent intent = new Intent(Intent.ACTION\_VIEW,Uri.parse(“https://example.com"));**

> **startActivity(intent);**

**Activity States and Configuration Changes**

**Problem: Rotation Resets State**

When you rotate the screen, the activity is recreated, potentially losing the data. To prevent this, override **onSaveInstanceState**().

**Example: Preserving State**

> **@Override**

> **protected void onSaveInstanceState(Bundle outState) {**

> **super.onSaveInstanceState(outState);**

> **outState.putString(“username”, username);**

> **}**

> **@Override**

> **protected void onRestoreInstanceState(Bundle savedInstanceState) {**

> **super.onRestoreInstanceState(savedInstanceState);**

> **username = savedInstanceState.getString(“username”);**

> **}**

💡 *Tip*: Use **ViewModel** or **LiveData** for better lifecycle management.

**Real-World Use Case**

For activities like notifications, where you want a specific screen to handle intents uniquely (e.g., singleTask for opening a detailed view).

#### **Pending Intents with Activities**

**PendingIntents** are often used with **Activities**, especially for:

- **Notifications**: Launching an activity when the user interacts with a notification.
- **Alarms**: Scheduling future activities with **AlarmManager**.

**Example:**

> **Intent intent = new Intent(context, NotificationActivity.class);**

> **PendingIntent pendingIntent = PendingIntent.getActivity(context, 0, intent, PendingIntent.FLAG\_UPDATE\_CURRENT);**

> **Notification notification = new NotificationCompat.Builder(context, CHANNEL\_ID)**

> **.setContentIntent(pendingIntent)**

> **.build();**

**Intent Filters and Deep Linking**

- **Deep Linking**: Allows apps to open specific activities via URLs.
- **Custom Actions**: Defining app-specific actions.

**Example (Deep Linking in Manifest):**

> **&lt;activity android:name=”.DeepLinkActivity”&gt;**

> **&lt;intent-filter&gt;**

> **&lt;action android:name=”android.intent.action.VIEW” /&gt;**

> **&lt;category android:name=”android.intent.category.DEFAULT” /&gt;**

> **&lt;category android:name=”android.intent.category.BROWSABLE” /&gt;**

> **&lt;data android:scheme=”https” android:host=”example.com” android:path=”/profile” /&gt;**

> **&lt;/intent-filter&gt;**

> **&lt;/activity&gt;**

**Security Best Practices**

- **Exported Activities**: Controlling whether an activity can be launched by other apps.
- **Data Validation**: Avoiding intent data tampering.
- **Protected Components**: Using **android:exported=”false**” for internal-only activities.

**Managing Memory with Activities**

- How Android handles activity processes under memory pressure.
- Using **onTrimMemory** to release resources when an app is in the background.

**Example (Using onTrimMemory):**

> **@Override**

> **public void onTrimMemory(int level) {**

> **if (level == ComponentCallbacks2.TRIM\_MEMORY\_UI\_HIDDEN) {**

> **// App is in the background**

> **}**

> **}**

#### 2. Services

Android **Service** component, a building block for performing long-running operations in the background without a user interface. Services are crucial for tasks like data synchronization, music playback, or handling network requests in the background.

**Service Lifecycle**: Explanation of lifecycle methods such as `onCreate()`, `onStartCommand()`, and `onDestroy()`.

![](https://cdn-images-1.medium.com/max/800/1*KT9fXIxtzQHFP-eNxKi2sA.png)

**Types of Services**:

- **Foreground Services**: Actively visible to the user via notifications (e.g., media playback).
- **Background Services**: Run without direct user interaction but are bound by system restrictions (e.g., data fetching).
- **Bound Services**: Allow components (like Activities) to bind to them for interprocess communication.

**Best Practices**: Emphasis on using modern APIs like **WorkManager** for battery-optimized background tasks.

#### Code Examples

1\. **Creating a Foreground Service**:

```
class MyForegroundService : Service() {
override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
val notification = NotificationCompat.Builder(this, CHANNEL_ID)
.setContentTitle("Foreground Service")
.setContentText("Running...")
.setSmallIcon(R.drawable.ic_notification)
.build()

startForeground(1, notification)
return START_STICKY
}

override fun onBind(intent: Intent): IBinder? = null
}
```

2\. **Using a Bound Service**:

```
class MyBoundService : Service() {
private val binder = LocalBinder()

inner class LocalBinder : Binder() {
fun getService(): MyBoundService = this@MyBoundService
}

override fun onBind(intent: Intent): IBinder = binder

fun fetchData(): String = "Data fetched from Bound Service"
}
```

Interaction between Activities and Services:

- **Foreground Service Example**: Activities can interact with foreground services via `BroadcastReceiver` to update UI or trigger actions.
- **Bound Service Example**: Activities use `ServiceConnection` to establish a persistent connection.

#### Modern Alternatives

- **WorkManager**: Highly recommended for periodic or scheduled background tasks that respect Android’s battery optimization policies. For example:

```
val workRequest = OneTimeWorkRequestBuilder<MyWorker>().build()
WorkManager.getInstance(context).enqueue(workRequest)
```

#### Permissions

Foreground services require explicit permissions like `FOREGROUND_SERVICE`**.** For instance:

```
<uses-permission android:name="android.permission.FOREGROUND_SERVICE"/>
```

#### Background Restrictions

Newer Android versions (e.g., Android 8.0+) impose strict restrictions on background services, pushing developers toward alternatives like **WorkManager** or **JobScheduler**.

#### Service Communication Mechanisms

Understanding how different components (Activities, BroadcastReceivers, other Services) interact with a Service is crucial.

#### a. Using Handlers and Messenger

- **Messenger**: Used to pass data between a Service and its clients (e.g., Activities) via messages.
- Example:

```
class MyService : Service() {
private val handler = Handler(Looper.getMainLooper()) { msg ->
// Process the received message
true
}
private val messenger = Messenger(handler)
override fun onBind(intent: Intent): IBinder = messenger.binder
}
```

#### b. BroadcastReceiver

- Services often use `BroadcastReceiver` to notify components about events.
- Example: A music app’s playback service broadcasts track change updates.

#### 2. Threading in Services

- Services run on the **main thread** by default, which can block UI operations if long-running tasks are executed.
- Developers should explicitly manage threading using:
- **Thread** or **HandlerThread**
- **Executors**
- **AsyncTask** (deprecated)
- **Coroutines** in Kotlin (modern alternative)

Example of using a `HandlerThread` in a Service:

```
class MyService : Service() {
private lateinit var handlerThread: HandlerThread
private lateinit var handler: Handler

override fun onCreate() {
handlerThread = HandlerThread("ServiceThread").apply { start() }
handler = Handler(handlerThread.looper)
}

override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
handler.post {
// Long-running task
}
return START_STICKY
}

override fun onDestroy() {
handlerThread.quitSafely()
}
}
```

#### Foreground Services and Notification Channels

- **Notification Channels** required for services targeting Android 8.0+.
- Foreground services must display a notification with a properly configured channel:

```
val channel = NotificationChannel(
"CHANNEL_ID", "Service Channel",
NotificationManager.IMPORTANCE_DEFAULT
)
val manager = getSystemService(NotificationManager::class.java)
manager.createNotificationChannel(channel)
```

#### Service Restrictions in Modern Android

Newer Android versions impose strict restrictions on services:

- **Android 8.0 (Oreo)**:
- Background execution limits restrict background services.
- Introduced **JobIntentService** as a replacement for **IntentService**.
- **Android 10**:
- Tightened background activity starts; services must adhere to user-initiated tasks.

Workarounds include using:

- **Foreground services**
- **WorkManager** or **JobScheduler**

#### Security and Permissions

- Services often handle sensitive operations (e.g., fetching user data). Securing them is vital:
- Use `android:permission` to restrict access.
- Example:

```
<service android:name=".MyService"
android:permission="com.example.MY_SERVICE_PERMISSION" />
```

#### Memory Management and Resource Handling

- Improper service use can lead to memory leaks or high resource consumption.
- **Best practices**:
- Always stop services when tasks are complete.
- Use `startForeground()` for long-running operations.
- Free resources (e.g., threads, listeners) in `onDestroy()`.

#### Real-world Use Cases

The article could have benefited from concrete, domain-specific examples:

- **Fitness Apps**: Using a bound service to continuously fetch location updates.
- **Media Players**: A foreground service for playback, allowing persistent controls.
- **Chat Apps**: Background services for real-time message synchronization.

### Content providers

Content providers can help an application manage access to data stored by itself or stored by other apps and provide a way to share data with other apps. They encapsulate the data and provide mechanisms for defining data security. Content providers are the standard interface that connects data in one process with code running in another process.

Implementing a content provider has many advantages. Most importantly, you can configure a content provider to let other applications securely access and modify your app data, as illustrated in figure 1.

![](https://cdn-images-1.medium.com/max/800/1*gTBKD27LwvAR4FGqO3Vn9g.png)

**Figure 1.** Overview diagram of how content providers manage access to storage.

Use content providers if you plan to share data. If you don’t plan to share data, you don’t have to use them, but you might choose to because they provide an abstraction that lets you make modifications to your application data storage implementation without affecting other applications that rely on access to your data.

In this scenario, only your content provider is affected and not the applications that access it. For example, you might swap out a SQLite database for alternative storage, as illustrated in figure 2.

![](https://cdn-images-1.medium.com/max/800/1*EkDw_PAtKQjzSToZtqh7-A.png)

**Figure 2.** Illustration of migrating content provider storage.

A number of other classes rely on the `ContentProvider` class:

· [AbstractThreadedSyncAdapter](https://developer.android.com/reference/android/content/AbstractThreadedSyncAdapter)

· [CursorAdapter](https://developer.android.com/reference/android/widget/CursorAdapter)

· [CursorLoader](https://developer.android.com/reference/android/content/CursorLoader)

If you use any of these classes, you need to implement a content provider in your application. When working with the sync adapter framework you can also create a stub content provider as an alternative. For more information, see [Create a stub content provider](https://developer.android.com/training/sync-adapters/creating-stub-provider). In addition, you need your own content provider in the following cases:

· To implement custom search suggestions in your application.

· To expose your application data to widgets.

· To copy and paste complex data or files from your application to other applications.

The Android framework includes content providers that manage data such as audio, video, images, and personal contact information. You can see some of them listed in the reference documentation for the `android.provider`package. With some restrictions, these providers are accessible to any Android application.

A content provider can be used to manage access to a variety of data storage sources, including both structured data, such as a SQLite relational database, or unstructured data such as image files. For more information about the types of storage available on Android, see the [Data and file storage overview](https://developer.android.com/guide/topics/data/data-storage) and [Design data storage](https://developer.android.com/guide/topics/providers/content-provider-creating#DataStorage).

#### Advantages of content providers

Content providers offer granular control over the permissions for accessing data. You can choose to restrict access to only a content provider that is within your application, grant blanket permission to access data from other applications, or configure different permissions for reading and writing data. For more information about using content providers securely, see the [security tips for data storage](https://developer.android.com/privacy-and-security/security-tips#StoringData) and [Content provider permissions](https://developer.android.com/guide/topics/providers/content-provider-basics#Permissions).

You can use a content provider to abstract away the details for accessing different data sources in your application. For example, your application might store structured records in a SQLite database, as well as video and audio files. You can use a content provider to access all of this data.

Also, `CursorLoader` objects rely on content providers to run asynchronous queries and then return the results to the UI layer in your application. For more information about using a `CursorLoader` to load data in the background, see [Loaders](https://developer.android.com/training/load-data-background/setup-loader).

### `BroadcastReceiver`

- Listens for broadcast messages from other apps or the system.
- Reacts to predefined events (e.g., `android.intent.action.BOOT_COMPLETED`) or custom intents.

#### Key Methods

The central method of a `BroadcastReceiver` is:

- `onReceive(Context context, Intent intent)`: Executes when the broadcast is received.

Example:

```
class BootReceiver : BroadcastReceiver() {
override fun onReceive(context: Context, intent: Intent) {
if (intent.action == Intent.ACTION_BOOT_COMPLETED) {
// Start a service or perform initialization
Toast.makeText(context, "Device Boot Completed", Toast.LENGTH_SHORT).show()
}
}
}
```

#### Types of Broadcasts

- **System Broadcasts**: Sent by the Android system for predefined actions, such as:
- `android.intent.action.AIRPLANE_MODE_CHANGED`
- `android.intent.action.BATTERY_LOW`
- **Custom Broadcasts**: Sent by apps for app-specific purposes.
- Example:

```
// Sending a custom broadcast
val intent = Intent("com.example.ACTION_CUSTOM_BROADCAST")
sendBroadcast(intent)
```

- **Sticky Broadcasts**: Deprecated since API level 21. The article does not explain their earlier use cases or modern alternatives like `SharedPreferences` or services.
- **LocalBroadcastManager**: A safer and more efficient way to broadcast within an app, avoiding security issues caused by global broadcasts.

#### Registering a BroadcastReceiver:

1\. **Manifest-declared (Static Registration)**:

- Ideal for receiving system-wide events.
- Example:

```
<receiver android:name=".BootReceiver">
<intent-filter>
<action android:name="android.intent.action.BOOT_COMPLETED" />
</intent-filter>
</receiver>
```

- Could benefit from clarifying modern restrictions:
- Starting with Android 8.0 (Oreo), background execution limits prevent implicit broadcasts for performance reasons unless explicitly whitelisted.

2\. **Programmatic Registration (Dynamic Registration)**:

- Used to register a receiver at runtime, often within an Activity or Service.
- Example:

```
val receiver = object : BroadcastReceiver() {
override fun onReceive(context: Context, intent: Intent) {
// Handle broadcast
}
}
val filter = IntentFilter(Intent.ACTION_BATTERY_LOW)
registerReceiver(receiver, filter)
```

#### Lifecycle Considerations

`onReceive` method's short lifecycle:

- `BroadcastReceiver` runs on the main thread, which means **long-running tasks should not be performed in** `onReceive`.
- Could add advice:
- Delegate work to a `Service` for longer tasks:

```
override fun onReceive(context: Context, intent: Intent) {
val serviceIntent = Intent(context, MyBackgroundService::class.java)
context.startService(serviceIntent)
}
```

#### Security Concerns

- Example:

```
<receiver android:name=".SecureReceiver">
<intent-filter>
<action android:name="com.example.SECURE_ACTION" />
</intent-filter>
<permission android:name="com.example.MY_PERMISSION" />
</receiver>
```

#### Broadcast Priority and Ordered Broadcasts

**Broadcast Priority**:

- When multiple receivers listen for the same intent, priority determines the order of execution.
- Example:

```
<receiver android:name=".HighPriorityReceiver">
<intent-filter android:priority="1000">
<action android:name="android.intent.action.BOOT_COMPLETED" />
</intent-filter>
</receiver>
```

- The `android:priority` attribute can range from -1000 to 1000.

**Ordered Broadcasts**:

- Allows broadcasts to be delivered to receivers one at a time in priority order.
- Receivers can:
- Stop further propagation using `abortBroadcast()`.
- Modify the broadcast intent before passing it to the next receiver.
- Example:

```
override fun onReceive(context: Context, intent: Intent) {
// Modify the intent
intent.putExtra("modified_data", "new_value")
abortBroadcast()  // Stop further propagation
}
```

#### . BroadcastReceiver Timeout

- The `onReceive()` method must execute quickly. If it takes too long, the system may kill the app due to the strict timeout of 10 seconds.
- Solution: For long-running tasks, start a Service or use `WorkManager` to handle the workload.

```
override fun onReceive(context: Context, intent: Intent) {
val workIntent = Intent(context, MyService::class.java)
context.startService(workIntent)
}
```

#### Sticky Broadcasts

- **Sticky broadcasts** are intents that remain available after being sent. They are used to provide constant updates (e.g., battery status).
- Example:

```
val batteryStatus = registerReceiver(null, IntentFilter(Intent.ACTION_BATTERY_CHANGED))
val level = batteryStatus?.getIntExtra(BatteryManager.EXTRA_LEVEL, -1)
```

- **Deprecated**: Starting with API 21, sticky broadcasts are discouraged due to security and performance reasons.

#### LocalBroadcastManager

- A safer, faster alternative to system-wide broadcasts when broadcasting within an application.

Advantages:

- Avoids external receivers from intercepting sensitive broadcasts.
- Eliminates security concerns like unintended data exposure.

Example:

```
val localBroadcastManager = LocalBroadcastManager.getInstance(context)
val intent = Intent("com.example.LOCAL_ACTION")
localBroadcastManager.sendBroadcast(intent)
```

#### Background Execution Limits in Modern Android

- Starting with Android 8.0 (Oreo), restrictions were imposed on implicit broadcasts to optimize battery life and performance.
- Many system broadcasts (e.g., `CONNECTIVITY_CHANGE`) cannot be received unless the app is in the foreground or explicitly declared in the manifest.
- **Workarounds**:
- Use `JobScheduler` or `WorkManager` for background tasks.
- Declare receivers for critical broadcasts in the manifest.

#### Permissions and Security

- Securing broadcasts is critical to avoid exploitation:
- **Restricting Receiver Visibility**:
- Use permissions to restrict which apps can send or receive broadcasts.

```
<receiver android:name=".SecureReceiver">
<intent-filter>
<action android:name="com.example.SECURE_ACTION" />
</intent-filter>
<permission android:name="com.example.MY_PERMISSION" />
</receiver>
```

- **Private Broadcasts**:
- Use `LocalBroadcastManager` to prevent other apps from intercepting sensitive data.
- **Exported Attribute**:
- Ensure `android:exported="false"` if the receiver is not meant to handle external broadcasts.

By [Moataz Osama](https://medium.com/@mezo512) on [February 13, 2025](https://medium.com/p/5e4358811107).

[Canonical link](https://medium.com/@mezo512/android-components-core-building-blocks-of-android-apps-5e4358811107)

Exported from [Medium](https://medium.com) on August 26, 2025.