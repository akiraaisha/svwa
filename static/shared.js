flash = function(msg) {
    clear_flash();
    $('#flash_container').append('<div class="flash">' + msg + '</div>');
};

clear_flash = function() {
    $('#flash_container').empty();
}
