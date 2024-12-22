use exhume_readers::ewf;
use exhume_readers::raw;
use log::info;
pub enum ImageFormat {
    RAW {
        image: raw::RAW,
        description: String,
    },
    EWF {
        image: ewf::EWF,
        description: String,
    }, // Other compatible image formats here
}
pub struct Image {
    path: String,
    format: ImageFormat,
}

impl Image {
    pub fn new(file_path: String) -> Image {
        // TODO: Determine the file format here (extension OR magic number ? )
        let image_format = 1;

        if image_format == 1 {
            let evidence = match ewf::EWF::new(&file_path) {
                Ok(ewf) => ewf,
                Err(message) => panic!("{}", message),
            };
            return Image {
                path: file_path,
                format: ImageFormat::EWF {
                    image: evidence,
                    description: "Expert Witness Compression Format".to_string(),
                },
            };
        } else {
            let evidence = match raw::RAW::new(&file_path) {
                Ok(evidence) => evidence,
                Err(message) => panic!("{}", message),
            };

            return Image {
                path: file_path,
                format: ImageFormat::RAW {
                    image: evidence,
                    description: "Expert Witness Compression Format".to_string(),
                },
            };
        }
    }

    pub fn print_info(&self) {
        info!("Evidence : {}", self.path);
    }

    pub fn read(&mut self, size: usize) -> Vec<u8> {
        match self.format {
            ImageFormat::EWF { ref mut image, .. } => image.read(size),
            ImageFormat::RAW { ref mut image, .. } => image.read(size),
            // All other compatible formats will be handled here.
        }
    }

    pub fn seek(&mut self, offset: usize) {
        match self.format {
            ImageFormat::EWF { ref mut image, .. } => image.seek(offset),
            ImageFormat::RAW { ref mut image, .. } => image.seek(offset),
            // All other compatible formats will be handled here.
        }
    }

    pub fn get_sector_size(&self) -> u16 {
        match &self.format {
            ImageFormat::EWF { image, .. } => image.get_sector_size(),
            ImageFormat::RAW { .. } => 512,
            // All other compatible formats will be handled here.
        }
    }
}
