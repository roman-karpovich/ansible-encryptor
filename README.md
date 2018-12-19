# ansible-encryptor
ansible-vault-encryptor


###encrypt all variables which are listed in encryptor.yml for every file in path:
./encryptor.py ../ansible


---


###view decrypted variables
./encryptor_view.py ../ansible roles/common/vars/staging/newrelic.yml > decrypted.yml
