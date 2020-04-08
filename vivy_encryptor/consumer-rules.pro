# vivy_encryptor

#Bouncy Castle

-dontwarn org.bouncycastle.**
-keep class org.bouncycastle.** { *; }

#Gson

# Gson uses generic type information stored in a class file when working with fields. Proguard
# removes such information by default, so configure it to keep all of it.
-keepattributes Signature

 # For using GSON @Expose annotation
-keepattributes *Annotation*

 # Gson specific classes
-dontwarn sun.misc.**

# Guava

-dontwarn sun.misc.Unsafe
-dontwarn com.google.common.collect.MinMaxPriorityQueue
