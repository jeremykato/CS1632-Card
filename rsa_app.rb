require_relative 'rsa_engine'

names_fn = 'names.txt'
key_dir = './keys'
card_fn = 'card.pdf'
signature_fn = 'signatures.txt'

def print_usage
  puts 'Usage: ruby rsa_app.rb <option>'
  puts '  options: -g generate'
  puts '           -s sign card'
  puts '           -v verify signatures'
end

if ARGV.size != 1
  print_usage
  return
elsif ARGV[0] != '-g' && ARGV[0] != '-s'
  print_usage
  return
end

if ARGV[0] == '-g'
  if File.file?(names_fn)
    lines = File.readlines(names_fn)
    lines.each do 
      |line| line.slice!("\n")
    end
    name_key_map = RSAEngine.generate(lines) # totally secure*
    RSAEngine.write_pem_files(key_dir, name_key_map) # also totally secure*
    puts 'Completed key generation!'
  else
    puts 'Error: '+ names_fn.to_s + ' not found!'
  end
elsif ARGV[0] == '-s'
  if File.file?(card_fn)
    name_key_pairs = RSAEngine.get_keys_from_dir(key_dir)
    card_bin = IO.binread(card_fn)
    name_signature_pairs = RSAEngine.sign_all(card_bin, name_key_pairs)
    RSAEngine.write_signatures_to_file(signature_fn, name_signature_pairs)
    puts 'Completed file signing! Cheers, Professor Laboon!'
  else
    puts 'Error: ' + card_fn.to_s + ' not found!'
  end
end

# *not at all secure
