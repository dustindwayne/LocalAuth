plugins { id("com.android.application"); id("org.jetbrains.kotlin.android") }
android {
 namespace = "com.localauth"
 compileSdk = 35
 defaultConfig { applicationId = "com.localauth"; minSdk = 28; targetSdk = 35; versionCode = 8; versionName = "4.0.1" }
 compileOptions { sourceCompatibility = JavaVersion.VERSION_17; targetCompatibility = JavaVersion.VERSION_17 }
 kotlinOptions { jvmTarget = "17" }
}
dependencies {
 implementation("androidx.fragment:fragment:1.8.6")
 implementation("androidx.activity:activity:1.10.1")
 implementation("com.journeyapps:zxing-android-embedded:4.3.0")
 testImplementation("junit:junit:4.13.2")
}
