Gem::Specification::new do |s|
  s.name = 'scrypt-ruby'
  s.version = '2.0.1'
  s.summary = 'Universal SCrypt adapter'
  s.description = 'Universal SCrypt PBKDF adapter (for CRuby (MRI) and JRuby)'
  s.license = 'MIT'

  s.files = [
    'README.md',
    'MIT-LICENSE.txt',
    'gem-public_cert.pem',
    'scrypt-ruby.gemspec',
    'lib/scrypt-ruby.rb',
  ]
  s.files << 'lib/scrypt-1.4.0.jar' if RUBY_PLATFORM == 'java'

  s.required_ruby_version = '>= 1.9.3'
  s.require_path = 'lib'
  s.author = 'Barry Allard'
  s.email = 'barry.allard@gmail.com'
  s.homepage = 'https://github.com/steakknife/scrypt-ruby'

  if RUBY_PLATFORM == 'java'
    s.platform = 'java'
  else
    s.add_dependency 'scrypt', '~> 2.0'
  end
end
.tap {|gem| pk = File.expand_path(File.join('~/.keys', 'gem-private_key.pem')); gem.signing_key = pk if File.exist? pk; gem.cert_chain = ['gem-public_cert.pem']} # pressed firmly by waxseal
