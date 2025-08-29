import './style.css'
import javascriptLogo from './javascript.svg'
import viteLogo from '/vite.svg'
import { listRecords } from './tauri.js';

async function afficherRecords() {
  try {
    const records = await listRecords();
    console.log('Enregistrements :', records);
  } catch (e) {
    console.error('Erreur :', e);
  }
}

afficherRecords();
import { setupCounter } from './counter.js'

document.querySelector('#app').innerHTML = `
  <div>
    <a href="https://vite.dev" target="_blank">
      <img src="${viteLogo}" class="logo" alt="Vite logo" />
    </a>
    <a href="https://developer.mozilla.org/en-US/docs/Web/JavaScript" target="_blank">
      <img src="${javascriptLogo}" class="logo vanilla" alt="JavaScript logo" />
    </a>
    <h1>Hello Vite!</h1>
    <div class="card">
      <button id="counter" type="button"></button>
    </div>
    <p class="read-the-docs">
      Click on the Vite logo to learn more
    </p>
  </div>
`

setupCounter(document.querySelector('#counter'))
