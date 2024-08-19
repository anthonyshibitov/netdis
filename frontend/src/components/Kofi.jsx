import React, { useEffect } from 'react';

const Kofi = () => {
  useEffect(() => {
    const script = document.createElement('script');
    script.src = 'https://storage.ko-fi.com/cdn/scripts/overlay-widget.js';
    script.async = true;

    document.body.appendChild(script);

    script.onload = () => {
      if (window.kofiWidgetOverlay) {
        window.kofiWidgetOverlay.draw('anthonyshibitov', {
          'type': 'floating-chat',
          'floating-chat.donateButton.text': 'Support me',
          'floating-chat.donateButton.background-color': '#00b9fe',
          'floating-chat.donateButton.text-color': '#fff'
        });
      }
    };

    return () => {
        // Remove kofi element
        const kofiWidgetElements = document.querySelectorAll('[id^="kofi-widget-overlay-"]');
        kofiWidgetElements.forEach(el => el.remove());
        document.body.removeChild(script);
    };
  }, []);

  return null;
};

export default Kofi;
