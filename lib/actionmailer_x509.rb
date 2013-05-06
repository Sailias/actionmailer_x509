# Copyright (c) 2007 Fabien Penso <fabien.penso@conovae.com>
#
# actionmailer_x509 is a rails plugin to allow X509 outgoing mail to be X509
# signed.
#
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
#     * Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above copyright
#       notice, this list of conditions and the following disclaimer in the
#       documentation and/or other materials provided with the distribution.
#     * Neither the name of the University of California, Berkeley nor the
#       names of its contributors may be used to endorse or promote products
#       derived from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND ANY
# EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE REGENTS AND CONTRIBUTORS BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
require 'actionmailer_x509/railtie' if defined?(Rails)
require "openssl"

module ActionMailer #:nodoc:
  class Base #:nodoc:

    attr_accessor :x509_settings

    # We replace the initialize methods and run a new method if signing or crypting is required
    def initialize_with_sign_and_crypt(method_name, *parameters)
      default_settings = {
        sign: false,
        crypt: false,
        p12: nil,
        crypt_cert: nil,
        crypt_cipher: :des,
        crypt_method: :smime,
        passphrase: nil,
        ca_cert: nil
      }

      initialize_without_sign_and_crypt(method_name, *parameters)
      mail = @_message

      @x509_settings = default_settings.merge @x509_settings

      # If we need to sign the outgoing mail.
      if should_sign? or should_crypt?
        if logger
          logger.debug("actionmailer_x509: We should sign and\or crypt the mail with #{@x509_settings[:crypt_method]} method.")
        end
        send("x509_#{@x509_settings[:crypt_method]}", mail)
      end
    end
    alias_method_chain :initialize, :sign_and_crypt

    # X509 SMIME signing and\or crypting
    def x509_smime(mail)
      if logger
        logger.debug("actionmailer_x509: X509 SMIME signing with p12 #{@x509_settings[:p12]}") if should_sign?
        logger.debug("actionmailer_x509: X509 SMIME crypt with cert #{@x509_settings[:crypt_cert]}") if should_crypt?
      end

      # We should set content_id, otherwise Mail will set content_id after signing and will broke sign
      mail.content_id ||= nil
      mail.parts.each {|p| p.content_id ||= nil}

      if @x509_settings[:ca_cert]
        ca_cert = OpenSSL::X509::Certificate.new( File::read(@x509_settings[:ca_cert]) )
      end

      # We load certificate and private key
      if @x509_settings[:sign]
        if @x509_settings[:p12]
          sign_p12 = OpenSSL::PKCS12.new(File.read(@x509_settings[:p12]), @x509_settings[:passphrase])

          sign_cert = sign_p12.certificate
          sign_prv_key = sign_p12.key
        elsif @x509_settings[:sign_cert] && @x509_settings[:sign_key]
          sign_cert = OpenSSL::X509::Certificate.new( File::read(@x509_settings[:sign_cert]) )
          sign_prv_key = OpenSSL::PKey::RSA.new( File::read(@x509_settings[:sign_key]), @x509_settings[:passphrase])
        else
          logger.info "X509 signing required, but no certificate and key files configured"
        end
      end

      if should_crypt?
        crypt_cert = OpenSSL::X509::Certificate.new( File::read(@x509_settings[:crypt_cert]) )
        cipher = OpenSSL::Cipher.new(@x509_settings[:crypt_cipher])
      end

      # Sign and crypt the mail
      # NOTE: the one following line is the slowest part of this code, signing is sloooow
      p7 = mail.encoded
      p7 = OpenSSL::PKCS7.sign(sign_cert, sign_prv_key, p7, [ca_cert || nil], OpenSSL::PKCS7::DETACHED) if sign_cert && sign_prv_key
      p7 = OpenSSL::PKCS7.encrypt([crypt_cert], (should_sign? ? OpenSSL::PKCS7::write_smime(p7) : p7), cipher, nil) if should_crypt?
      smime0 = OpenSSL::PKCS7::write_smime(p7)

      # Adding the signature part to the older mail
      newm = Mail.new(smime0)

      # We need to overwrite the content-type of the mail so MUA notices this is a signed mail
      newm.delivery_method(mail.delivery_method.class, mail.delivery_method.settings)
      newm.subject = mail.subject
      newm.to = mail.to
      newm.cc = mail.cc
      newm.from = mail.from
      newm.mime_version = mail.mime_version
      newm.date = mail.date
      @_message = newm
    end

    protected

    def should_sign?
      @x509_settings[:p12] || (@x509_settings[:sign_cert] && @x509_settings[:sign_key])
    end

    # Shall we crypt the mail?
    def should_crypt?
      crypt = @x509_settings[:crypt] && @x509_settings[:crypt_cert]
      logger.info "X509 crypting required, but no certificate file configured" unless crypt
      crypt
    end
  end
end
