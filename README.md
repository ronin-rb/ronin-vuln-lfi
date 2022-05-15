# ronin-vuln-lfi

[![CI](https://github.com/ronin-rb/ronin-vuln-lfi/actions/workflows/ruby.yml/badge.svg)](https://github.com/ronin-rb/ronin-vuln-lfi/actions/workflows/ruby.yml)
[![Code Climate](https://codeclimate.com/github/ronin-rb/ronin-vuln-lfi.svg)](https://codeclimate.com/github/ronin-rb/ronin-vuln-lfi)

* [Website](https://ronin-rb.dev/)
* [Source](https://github.com/ronin-rb/ronin-vuln-lfi)
* [Issues](https://github.com/ronin-rb/ronin-vuln-lfi/issues)
* [Documentation](https://ronin-rb.dev/docs/ronin-vuln-lfi/frames)
* [Slack](https://ronin-rb.slack.com) |
  [Discord](https://discord.gg/6WAb3PsVX9) |
  [Twitter](https://twitter.com/ronin_rb)

## Description

ronin-vuln-lfi is a small Ruby library to test for Local File Inclusion (LFI)
vulnerabilities.

## Features

* Provides tests for Location File Inclusion (LFI).

## Examples

Test for Local File Inclusion (LFI):

    require 'ronin/php/lfi'

    url = URI('http://www.example.com/site.php?page=home')
    url.has_lfi?
    # => true

Get the first viable LFI vulnerability:

    url.first_lfi
    # => #<Ronin::PHP::LFI: ...>

Scan a URL for LFI vulnerabilities:

    url.lfi_scan
    # => [#<Ronin::PHP::LFI: ...>, ...]

## Requirements

* [Ruby] >= 3.0.0
* [ronin-support] ~> 1.0

## Install

```shell
$ gem install ronin-vuln-lfi
```

### Gemfile

```ruby
gem 'ronin-vuln-lfi', '~> 0.1'
```

### gemspec

```ruby
gem.add_dependency 'ronin-vuln-lfi', '~> 0.1'
```

## Development

1. [Fork It!](https://github.com/ronin-rb/ronin-vuln-lfi/fork)
2. Clone It!
3. `cd ronin-vuln-lfi/`
4. `bundle install`
5. `git checkout -b my_feature`
6. Code It!
7. `bundle exec rake spec`
8. `git push origin my_feature`

## License

Copyright (c) 2007-2022 Hal Brodigan (postmodern.mod3 at gmail.com)

This file is part of ronin-vuln-lfi.

ronin-vuln-lfi is free software: you can redistribute it and/or modify
it under the terms of the GNU Lesser General Public License as published
by the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

ronin-vuln-lfi is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public License
along with ronin-vuln-lfi.  If not, see <https://www.gnu.org/licenses/>.

[Ruby]: https://www.ruby-lang.org
[ronin-support]: https://github.com/ronin-rb/ronin-support#readme
