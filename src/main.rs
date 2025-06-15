use clap::Parser;
use serde_json::{Value, from_slice, to_string_pretty};
use base64::{Engine as _, engine::general_purpose::{URL_SAFE, URL_SAFE_NO_PAD}};
use flate2::{read::ZlibDecoder, write::ZlibEncoder, Compression};
use std::io::{Read, Write};
use std::fs;
use std::path::PathBuf;
use thiserror::Error;

#[derive(Error, Debug)]
enum AppError {
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    JsonError(#[from] serde_json::Error),
    #[error("Base64 decode error: {0}")]
    Base64DecodeError(#[from] base64::DecodeError),
    #[error("Zlib decompression error: {0}")]
    ZlibDecompressionError(String), // Represent zlib error as a string, or wrap std::io::Error explicitly
    #[error("Invalid data format: Missing vpn:// prefix")]
    InvalidFormatMissingPrefix,
    #[error("Invalid data length after decompression")]
    InvalidDataLength,
    #[error("Invalid arguments: Cannot specify more than one input source (encoded string, --input, or --decode-file)")]
    InvalidArgumentsMultipleInputs,
    #[error("No arguments provided. Use --help for usage.")]
    NoArguments,
}

/// Converts AmneziaVPN configuration between Base64 string and JSON.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None, arg_required_else_help = true)]
struct Args {
    /// Base64 string with "vpn://" prefix containing AmneziaVPN configuration.
    /// Cannot be used with --input or --decode-file.
    #[arg(value_name = "vpn://...", conflicts_with_all = ["input", "decode_file"])]
    encoded_string: Option<String>,

    /// Path to JSON file to read configuration for encoding.
    /// Cannot be used with the encoded string argument or --decode-file.
    #[arg(short, long, value_name = "input.json", conflicts_with_all = ["encoded_string", "decode_file"])]
    input: Option<PathBuf>,

    /// Path to a file containing the Base64 string with "vpn://" prefix to decode.
    /// Cannot be used with the encoded string argument or --input.
    #[arg(short = 'd', long = "decode-file", value_name = "encoded.vpn", conflicts_with_all = ["encoded_string", "input"])]
    decode_file: Option<PathBuf>,

    /// Path to JSON file to write decoded configuration.
    /// If not specified, configuration will be printed to console.
    #[arg(short, long, value_name = "output.json")]
    output: Option<PathBuf>,
}

fn encode_config(config: &Value) -> Result<String, AppError> {
    // Use indent=4 to preserve indentation
    let json_str = to_string_pretty(config)?.into_bytes();
    let original_data_len = json_str.len();

    // Compress data using zlib
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(&json_str)?;
    let compressed_data = encoder.finish()?;

    // Add a 4-byte header with the original data length in big-endian format
    let header = (original_data_len as u32).to_be_bytes();

    // Combine header and compressed data, then encode with Base64
    let mut combined_data = Vec::with_capacity(header.len() + compressed_data.len());
    combined_data.extend_from_slice(&header);
    combined_data.extend_from_slice(&compressed_data);

    let encoded_data = URL_SAFE_NO_PAD.encode(&combined_data);

    Ok(format!("vpn://{}", encoded_data))
}

fn decode_config(encoded_string: &str) -> Result<Value, AppError> {
    let encoded_data_without_prefix = encoded_string.strip_prefix("vpn://").ok_or(AppError::InvalidFormatMissingPrefix)?;

    // Add back padding removed by Python encoder
    let padding_len = (4 - encoded_data_without_prefix.len() % 4) % 4;
    let encoded_data = encoded_data_without_prefix.to_string() + &"=".repeat(padding_len);

    // Base64 decode
    let compressed_data = URL_SAFE.decode(&encoded_data)?;

    if compressed_data.len() < 4 {
         // If data is too short to contain header, treat as uncompressed base64 JSON
         return Ok(from_slice(&compressed_data)?);
    }

    // Try to decompress the data assuming it's zlib compressed
    let original_data_len = u32::from_be_bytes([
        compressed_data[0],
        compressed_data[1],
        compressed_data[2],
        compressed_data[3],
    ]) as usize;

    let mut decoder = ZlibDecoder::new(&compressed_data[4..]);
    let mut decompressed_data = Vec::new();

    match decoder.read_to_end(&mut decompressed_data) {
        Ok(_) => {
            if decompressed_data.len() != original_data_len {
                // If decompression succeeds but length doesn't match header, might still be just base64 JSON or invalid data
                 // Attempting to load as JSON directly, as Python code fallback suggests
                 match from_slice(&compressed_data) {
                     Ok(val) => Ok(val),
                     Err(_) => Err(AppError::InvalidDataLength), // If direct JSON also fails, it's invalid
                 }
            } else {
                // Decompression successful and length matches
                Ok(from_slice(&decompressed_data)?)
            }
        },
        Err(e) => {
            // If zlib decompression fails, assume the data is just base64 encoded JSON
             // Also, capture the zlib error if we want to report it
            match from_slice(&compressed_data) {
                Ok(val) => Ok(val),
                Err(json_err) => Err(AppError::ZlibDecompressionError(format!("Zlib failed: {}, JSON failed: {}", e, json_err))),
            }
        }
    }
}

fn main() -> Result<(), AppError> {
    let args = Args::parse();

    // Determine the source of the encoded string to decode
    let encoded_string_to_decode: Option<String> = if let Some(input_path) = args.input {
        // Case 1: Encode JSON from file
        let file_content = fs::read_to_string(&input_path)?;
        let config: Value = from_slice(file_content.as_bytes())?;
        let encoded_string = encode_config(&config)?;
        println!("Encoded string:\n{}", encoded_string);
        return Ok(()); // Exit after encoding
    } else if let Some(encoded_string) = args.encoded_string {
        // Case 2: Decode Base64 string from command line argument
        Some(encoded_string)
    } else if let Some(decode_file_path) = args.decode_file {
        // Case 3: Decode Base64 string from file
        fs::read_to_string(&decode_file_path).map(Some)?
    } else {
        // Case 4: No arguments provided (should be handled by clap's arg_required_else_help)
        // This branch should ideally not be reached due to arg_required_else_help = true
        return Err(AppError::NoArguments);
    };

    // If we have an encoded string (Case 2 or 3), proceed with decoding
    if let Some(encoded_string) = encoded_string_to_decode {
        let config = decode_config(&encoded_string)?;
        let json_output = to_string_pretty(&config)?;

        if let Some(output_path) = args.output {
            fs::write(&output_path, json_output)?;
            println!("Configuration saved to {}", output_path.display());
        } else {
            println!("{}", json_output);
        }
    }

    Ok(())
}
