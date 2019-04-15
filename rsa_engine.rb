require 'openssl'
require 'base64'
require 'digest'

# RSA Engine
class RSAEngine
  def self.generate(lines)
    name_kp_map = {}
    lines.each do |name|
      name_kp_map[name] = OpenSSL::PKey::RSA.new(2048).to_pem
    end
    name_kp_map
  end

  def self.sign_all(message, name_key_map)
    message_hash = Digest::SHA256.base64digest(message)
    name_sig_map = {}
    name_key_map.keys.each do |name|
      name_sig_map[name] = name_key_map[name].private_encrypt(message_hash)
    end
    name_sig_map
  end

  def self.write_pem_files(directory, name_key_map)
    Dir.mkdir directory unless Dir.exist? directory
    name_key_map.keys.each do |name|
      name = name.delete("\n")
      filename = directory + '/' + name + '.pem'
      File.open(filename, 'w+') do |f|
        f.write(name_key_map[name])
      end
    end
  end

  def self.get_keys_from_dir(directory)
    map = {}
    Dir[directory + '/*.pem'].each do |pem_file|
      pem = File.readlines(pem_file).join('')
      key = OpenSSL::PKey::RSA.new(pem)
      pem_file.slice!(directory)
      pem_file.slice!('.pem')
      map[pem_file] = key
    end
    map
  end

  def self.write_signatures_to_file(filename, name_sig_map)
    File.write(filename, "Signatures:\n", mode: 'w+')
    name_sig_map.keys.each do |name|
      str = name + ': ' + Base64.encode64(name_sig_map[name]) + "\n"
      File.write(filename, str, mode: 'a')
    end
  end
end
