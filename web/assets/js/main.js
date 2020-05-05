$(document).ready(function(){
    // Collapse error details.
    $('.collapse.show')
        .removeClass('show')
        .siblings('.card-header')
        .addClass('collapsed');

    // Add shadow under navbar if the page is scrolled already on load.
    $(document).scroll(function() {
        var scrolled = $(this).scrollTop();
        if(scrolled > 50) {
            $(".navbar").addClass('navbar-scrolled');
        } else {
            $(".navbar").removeClass('navbar-scrolled');
        }
    });
});