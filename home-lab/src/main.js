import './console-bridge.js';
import './style.css';
import gsap from 'gsap';
import { installUiRefreshListener } from './ui-refresh.js';
import './components/toast.js';
import './components/dns-status.js';
import './components/dns-records.js';
import './components/http-status.js';
import './components/http-routes.js';
import './components/s3-status.js';
import './components/s3-buckets.js';
import './components/oidc-status.js';
import './components/oidc-clients.js';
import './components/wsl-instance.js';
import './components/k8s-client.js';

installUiRefreshListener();

// Animation d'entrée au chargement de l'application
document.addEventListener("DOMContentLoaded", () => {
  const tl = gsap.timeline();

  // Animation du header
  tl.to(".gsap-header", {
    y: 0,
    opacity: 1,
    duration: 0.6,
    ease: "power3.out",
    clearProps: "all" 
  })
  // Animation en cascade (stagger) des cartes du dashboard
  .to(".gsap-card", {
    y: 0,
    opacity: 1,
    duration: 0.5,
    stagger: 0.05, // Effet d'apparition séquentielle
    ease: "back.out(1.7)",
    clearProps: "all"
  }, "-=0.4"); // Commence un peu avant la fin de l'animation du header
});
