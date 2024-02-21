// [START initialize_firebase_in_sw]
// Give the service worker access to Firebase Messaging.
// Note that you can only use Firebase Messaging here, other Firebase libraries
// are not available in the service worker.
importScripts('https://www.gstatic.com/firebasejs/3.5.2/firebase-app.js');
importScripts('https://www.gstatic.com/firebasejs/3.5.2/firebase-messaging.js');

// Initialize the Firebase app in the service worker by passing in the
// messagingSenderId.
firebase.initializeApp({
  apiKey: "AAAAZBOc8No:APA91bGxl4An4Rij5iO7Nv0fCjEe4a1Q_uTT-EiwVfy_nL6vmeuRMFjOGNFcz_Z6cqQN5al6UiEy3ZxzyTMhKbtMq-fCk-sZDXsV0InXn9ZyaINinkoZzj0N4a-t8Jh9jmroBrbVq13U",
  authDomain: "dialogue-social-app.firebaseapp.com",
  databaseURL: "https://dialogue-social-app.firebaseio.com",
  projectId: "dialogue-social-app",
  storageBucket: "dialogue-social-app.appspot.com",
  messagingSenderId: "429825781978"
});

// Retrieve an instance of Firebase Messaging so that it can handle background
// messages.
const messaging = firebase.messaging();
// [END initialize_firebase_in_sw]

// If you would like to customize notifications that are received in the
// background (Web app is closed or not in browser focus) then you should
// implement this optional method.
// [START background_handler]
messaging.setBackgroundMessageHandler(function(payload) {
  console.log('[firebase-messaging-sw.js] Received background message ', payload);
  // Customize notification here
  const notificationTitle = 'Background Message Title';
  const notificationOptions = {
    body: 'Background Message body.'
  };

  return self.registration.showNotification(notificationTitle,
      notificationOptions);
});
// [END background_handler]