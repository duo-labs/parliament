class Parliament < Formula
  include Language::Python::Virtualenv

  desc "Shiny new formula"
  homepage "https://github.com/duo-labs/parliament"
  url "https://files.pythonhosted.org/packages/26/6e/fcdd825b3bf5f1921594fe68260885888d20c7c8d55645b2a4a120d1c712/parliament-0.4.12.tar.gz"
  sha256 "5f3639ccd7022b880bc4247a9f13b1e9d8a8a289e9289780a848a6880cbdfb35"

  depends_on "python3"

  resource "boto3" do
    url "https://files.pythonhosted.org/packages/6c/32/29c82f06eb8269ed87a7c3c5c2a6197e7f36f448f8eb7517295caa4b033d/boto3-1.12.47.tar.gz"
    sha256 "84daba6d2f0c8d55477ba0b8196ffa7eb7f79d9099f768ac93eb968955877a3f"
  end

  resource "botocore" do
    url "https://files.pythonhosted.org/packages/8a/21/9749eaf2b3edc37df772f9e3d1c67692fff68dbc2baeb913fb48b505fbca/botocore-1.15.47.tar.gz"
    sha256 "6c6e9db7a6e420431794faee111923e4627b4920d4d9d8b16e1a578a389b2283"
  end

  resource "docutils" do
    url "https://files.pythonhosted.org/packages/93/22/953e071b589b0b1fee420ab06a0d15e5aa0c7470eb9966d60393ce58ad61/docutils-0.15.2.tar.gz"
    sha256 "a2aeea129088da402665e92e0b25b04b073c04b2dce4ab65caaa38b7ce2e1a99"
  end

  resource "jmespath" do
    url "https://files.pythonhosted.org/packages/5c/40/3bed01fc17e2bb1b02633efc29878dfa25da479ad19a69cfb11d2b88ea8e/jmespath-0.9.5.tar.gz"
    sha256 "cca55c8d153173e21baa59983015ad0daf603f9cb799904ff057bfb8ff8dc2d9"
  end

  resource "python-dateutil" do
    url "https://files.pythonhosted.org/packages/be/ed/5bbc91f03fa4c839c4c7360375da77f9659af5f7086b7a7bdda65771c8e0/python-dateutil-2.8.1.tar.gz"
    sha256 "73ebfe9dbf22e832286dafa60473e4cd239f8592f699aa5adaf10050e6e1823c"
  end

  resource "PyYAML" do
    url "https://files.pythonhosted.org/packages/64/c2/b80047c7ac2478f9501676c988a5411ed5572f35d1beff9cae07d321512c/PyYAML-5.3.1.tar.gz"
    sha256 "b8eac752c5e14d3eca0e6dd9199cd627518cb5ec06add0de9d32baeee6fe645d"
  end

  resource "s3transfer" do
    url "https://files.pythonhosted.org/packages/50/de/2b688c062107942486c81a739383b1432a72717d9a85a6a1a692f003c70c/s3transfer-0.3.3.tar.gz"
    sha256 "921a37e2aefc64145e7b73d50c71bb4f26f46e4c9f414dc648c6245ff92cf7db"
  end

  resource "six" do
    url "https://files.pythonhosted.org/packages/21/9f/b251f7f8a76dec1d6651be194dfba8fb8d7781d10ab3987190de8391d08e/six-1.14.0.tar.gz"
    sha256 "236bdbdce46e6e6a3d61a337c0f8b763ca1e8717c03b369e87a7ec7ce1319c0a"
  end

  resource "urllib3" do
    url "https://files.pythonhosted.org/packages/05/8c/40cd6949373e23081b3ea20d5594ae523e681b6f472e600fbc95ed046a36/urllib3-1.25.9.tar.gz"
    sha256 "3018294ebefce6572a474f0604c2021e33b3fd8006ecd11d62107a5d2a963527"
  end

  def install
    virtualenv_create(libexec, "python3")
    virtualenv_install_with_resources
  end

  test do
    false
  end
end
