use std::{collections::HashMap, fs, path::PathBuf, sync::Mutex};

use tauri::{image::Image, AppHandle, Manager};

use resvg::{
    tiny_skia::{Pixmap, Transform},
    usvg::{self, Options, Tree},
};

/// États d'icônes (détermine la couleur appliquée)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[allow(dead_code)]
pub enum IconState {
    Ok,
    Warning,
    Down,
}

/// Couleur (RGB) par état
fn color_for_state(state: IconState) -> (u8, u8, u8) {
    match state {
        IconState::Ok => (0x00, 0xC8, 0x53),      // vert
        IconState::Warning => (0xFF, 0xB3, 0x00), // orange
        IconState::Down => (0xD5, 0x00, 0x00),    // rouge
    }
}

/// Injecte une balise <style> dans le SVG pour forcer fill/stroke
fn recolor_svg(svg_text: &str, rgb: (u8, u8, u8)) -> String {
    let (r, g, b) = rgb;
    let hex = format!("#{r:02X}{g:02X}{b:02X}");

    if let Some(pos) = svg_text.find('>') {
        let (head, tail) = svg_text.split_at(pos + 1);
        let style = format!(
            r#"<style>
* {{ fill: {c}; stroke: {c}; }}
text {{ fill: {c}; }}
</style>"#,
            c = hex
        );
        format!("{head}{style}{tail}")
    } else {
        // SVG étrange : on re-wrap dans un <svg> minimal
        format!(
            r#"<svg xmlns="http://www.w3.org/2000/svg"><style>*{{fill:{c};stroke:{c};}} text{{fill:{c};}}</style>{orig}</svg>"#,
            c = hex,
            orig = svg_text
        )
    }
}

/// Gestionnaire d'icônes avec cache (pixels RGBA8)
pub struct Icons {
    size: u32,
    /// cache[(name, state)] => RGBA8 (vec)
    cache: Mutex<HashMap<(String, IconState), Vec<u8>>>,
}

impl Icons {
    /// Crée un gestionnaire à la taille (carrée) souhaitée, ex: 20
    pub fn load(_app: &AppHandle, size: u32) -> tauri::Result<Self> {
        Ok(Self {
            size,
            cache: Mutex::new(HashMap::new()),
        })
    }

    /// Récupère une icône (par ex. `get("dns", IconState::Ok, app)`).
    /// Retourne directement un `tauri::image::Image<'static>`.
    pub fn get(
        &self,
        name: &str,
        state: IconState,
        app: &AppHandle,
    ) -> tauri::Result<Image<'static>> {
        let key = (name.to_string(), state);

        // 1) cache pixels -> Image
        if let Some(pixels) = self.cache.lock().unwrap().get(&key) {
            return Ok(Image::new_owned(pixels.clone(), self.size, self.size));
        }

        // 2) charge + recolorise
        let svg_path = resolve_icon_path(app, name)?;
        let svg_bytes = fs::read(&svg_path).map_err(|e| {
            tauri::Error::AssetNotFound(format!("Impossible de lire {}: {e}", svg_path.display()))
        })?;

        let svg_text = String::from_utf8(svg_bytes).map_err(|e| {
            tauri::Error::AssetNotFound(format!("SVG invalide (UTF-8) {}: {e}", svg_path.display()))
        })?;

        let recolored = recolor_svg(&svg_text, color_for_state(state));

        // 3) rasterize
        let img = rasterize_svg_to_image(recolored.as_bytes(), self.size)?;

        // 4) stocke les pixels dans le cache
        let mut map = self.cache.lock().unwrap();
        map.insert(key, img.rgba().to_vec());

        Ok(img)
    }
}

/// Construit le chemin `resources/icons/{name}.svg`
fn resolve_icon_path(app: &AppHandle, name: &str) -> tauri::Result<PathBuf> {
    // Avec Tauri 2.7, resource_dir() -> Result<PathBuf>
    let mut p = app.path().resource_dir()?;
    p.push("icons");
    p.push(format!("{name}.svg"));
    Ok(p)
}

/// Parse l’SVG et render dans un Pixmap (resvg 0.44 n’a plus FitTo).
fn rasterize_svg_to_image(svg_bytes: &[u8], size: u32) -> tauri::Result<Image<'static>> {
    let opt = Options::default();
    let tree: Tree = usvg::Tree::from_data(svg_bytes, &opt)
        .map_err(|e| tauri::Error::AssetNotFound(format!("Erreur parsing SVG: {e:?}")))?;

    // Récupère taille logique du SVG
    let ws = tree.size().width();
    let hs = tree.size().height();

    // Pixmap carré
    let mut pixmap = Pixmap::new(size, size)
        .ok_or_else(|| tauri::Error::AssetNotFound("Allocation Pixmap échouée".into()))?;

    // Calcul d’un scale uniforme pour contenir le SVG dans le carré
    let scale = (size as f32 / ws).min(size as f32 / hs);
    let tx = ((size as f32 - ws * scale) * 0.5).round();
    let ty = ((size as f32 - hs * scale) * 0.5).round();

    // Transform (translation + scale)
    let transform = Transform::from_translate(tx, ty).post_scale(scale, scale);

    // Rendu
    resvg::render(&tree, transform, &mut pixmap.as_mut());

    // Vers Image Tauri
    let rgba = pixmap.data().to_vec();
    Ok(Image::new_owned(rgba, size, size))
}
