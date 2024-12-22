mod extfs;
mod image;

use image::Image;
fn main() {
    println!("Hello, world!");
    let _img: Image = Image::new("test".to_string());
}
